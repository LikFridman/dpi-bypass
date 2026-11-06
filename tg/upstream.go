package tg

// Внешние прокси для Telegram: свой MTProto-прокси (ссылка tg://proxy?...)
// или SOCKS5 (socks5://host:port). Используются как запасной способ, если
// WebSocket к web.telegram.org не проходит.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Upstream - разобранная ссылка на внешний прокси.
type Upstream struct {
	Kind   string // "mtproto" или "socks5"
	Addr   string // host:port
	Key    []byte // 16 байт ключа MTProto-прокси
	Domain string // для FakeTLS (секрет ee...)
}

func (u Upstream) String() string {
	switch {
	case u.Kind == "socks5":
		return "SOCKS5 " + u.Addr
	case u.Domain != "":
		return "MTProto " + u.Addr + " (FakeTLS)"
	default:
		return "MTProto " + u.Addr
	}
}

// ParseUpstream понимает tg://proxy?server=..&port=..&secret=..,
// https://t.me/proxy?..., socks5://host:port и tg://socks?server=..&port=..
func ParseUpstream(link string) (Upstream, error) {
	link = strings.TrimSpace(link)
	var u Upstream
	pu, err := url.Parse(link)
	if err != nil {
		return u, err
	}
	q := pu.Query()
	switch {
	case pu.Scheme == "socks5" || pu.Scheme == "socks5h":
		if pu.Host == "" {
			return u, errors.New("нет адреса SOCKS5")
		}
		return Upstream{Kind: "socks5", Addr: withPort(pu.Host, "1080")}, nil
	case (pu.Scheme == "tg" && pu.Host == "socks") || strings.HasSuffix(pu.Path, "/socks"):
		if q.Get("server") == "" {
			return u, errors.New("нет server в ссылке")
		}
		return Upstream{Kind: "socks5", Addr: net.JoinHostPort(q.Get("server"), def(q.Get("port"), "1080"))}, nil
	case (pu.Scheme == "tg" && pu.Host == "proxy") || strings.HasSuffix(pu.Path, "/proxy"):
		if q.Get("server") == "" || q.Get("secret") == "" {
			return u, errors.New("в ссылке нет server или secret")
		}
		u = Upstream{Kind: "mtproto", Addr: net.JoinHostPort(q.Get("server"), def(q.Get("port"), "443"))}
		sec, err := decodeSecret(q.Get("secret"))
		if err != nil {
			return u, err
		}
		switch {
		case len(sec) == 16:
			u.Key = sec
		case len(sec) == 17 && sec[0] == 0xdd:
			u.Key = sec[1:]
		case len(sec) > 17 && sec[0] == 0xee:
			u.Key, u.Domain = sec[1:17], string(sec[17:])
		default:
			return u, errors.New("непонятный секрет прокси")
		}
		return u, nil
	}
	return u, errors.New("нужна ссылка tg://proxy?... или socks5://host:port")
}

func def(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func withPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, port)
}

func decodeSecret(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("секрет не в hex и не в base64")
}

// Route превращает внешний прокси в способ связи с Telegram.
func (u Upstream) Route() TGRoute {
	name := "прокси " + u.String()
	if u.Kind == "socks5" {
		return SocksRoute(name, u.Addr)
	}
	return TGRoute{Name: name, RelaySecret: u.Key, TCP: func(dc int) (net.Conn, string, error) {
		var c net.Conn
		var err error
		if u.Domain != "" {
			c, err = fakeTLSDial(u.Addr, u.Key, u.Domain)
		} else {
			c, err = directDial(u.Addr)
		}
		return c, u.Addr, err
	}}
}

// ---------- FakeTLS (секреты ee...) ----------
// Прокси с таким секретом ждёт начало, похожее на TLS 1.3 к сайту Domain:
// ClientHello, в поле random которого HMAC от ключа, а дальше трафик в записях TLS.

func fakeTLSHello(key []byte, domain string, now time.Time) []byte {
	be16 := func(n int) []byte { return []byte{byte(n >> 8), byte(n)} }
	ext := func(typ int, body []byte) []byte { return append(append(be16(typ), be16(len(body))...), body...) }
	rnd := func(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
	grease := func() []byte { g := byte(rnd(1)[0]&0xf0 | 0x0a); return []byte{g, g} }

	var exts []byte
	exts = append(exts, ext(int(binary.BigEndian.Uint16(grease())), nil)...)
	sni := append([]byte{0}, append(be16(len(domain)), domain...)...)
	exts = append(exts, ext(0x0000, append(be16(len(sni)), sni...))...)
	exts = append(exts, ext(0x0017, nil)...)
	exts = append(exts, ext(0xff01, []byte{0})...)
	exts = append(exts, ext(0x000a, []byte{0, 6, 0, 0x1d, 0, 0x17, 0, 0x18})...)
	exts = append(exts, ext(0x000b, []byte{1, 0})...)
	exts = append(exts, ext(0x0023, nil)...)
	alpn := []byte{2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	exts = append(exts, ext(0x0010, append(be16(len(alpn)), alpn...))...)
	exts = append(exts, ext(0x0005, []byte{1, 0, 0, 0, 0})...)
	sig := []byte{4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1}
	exts = append(exts, ext(0x000d, append(be16(len(sig)), sig...))...)
	exts = append(exts, ext(0x0012, nil)...)
	ks := append([]byte{0, 0x1d, 0, 32}, rnd(32)...)
	exts = append(exts, ext(0x0033, append(be16(len(ks)), ks...))...)
	exts = append(exts, ext(0x002d, []byte{1, 1})...)
	exts = append(exts, ext(0x002b, []byte{4, 3, 4, 3, 3})...)

	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...) // random - заполним ниже
	body = append(body, 32)
	body = append(body, rnd(32)...) // session id
	suites := []byte{0x13, 1, 0x13, 2, 0x13, 3, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0, 0x9c, 0, 0x9d, 0, 0x2f, 0, 0x35}
	suites = append(grease(), suites...)
	body = append(body, be16(len(suites))...)
	body = append(body, suites...)
	body = append(body, 1, 0)
	// дополнить до 517 байт, как браузер
	const total = 517
	cur := 5 + 4 + len(body) + 2 + len(exts)
	if pad := total - cur - 4; pad >= 0 {
		exts = append(exts, ext(0x0015, make([]byte, pad))...)
	}
	body = append(body, be16(len(exts))...)
	body = append(body, exts...)

	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 3, 1}, be16(len(hs))...)
	rec = append(rec, hs...)

	mac := hmac.New(sha256.New, key)
	mac.Write(rec)
	digest := mac.Sum(nil)
	ts := uint32(now.Unix())
	for i := 0; i < 4; i++ {
		digest[28+i] ^= byte(ts >> (8 * i))
	}
	copy(rec[11:43], digest)
	return rec
}

func readTLSRecord(r io.Reader) (typ byte, rec []byte, err error) {
	h := make([]byte, 5)
	if _, err = io.ReadFull(r, h); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(h[3:5]))
	if h[1] != 3 || n > 1<<15 {
		return 0, nil, errors.New("FakeTLS: прокси ответил не TLS")
	}
	rec = make([]byte, 5+n)
	copy(rec, h)
	_, err = io.ReadFull(r, rec[5:])
	return h[0], rec, err
}

func fakeTLSDial(addr string, key []byte, domain string) (net.Conn, error) {
	c, err := directDial(addr)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	hello := fakeTLSHello(key, domain, time.Now())
	if _, err := c.Write(hello); err != nil {
		c.Close()
		return nil, err
	}
	// ServerHello, ChangeCipherSpec и запись с данными
	var resp []byte
	for i, want := range []byte{0x16, 0x14, 0x17} {
		typ, rec, err := readTLSRecord(c)
		if err != nil {
			c.Close()
			return nil, err
		}
		if typ != want {
			c.Close()
			return nil, fmt.Errorf("FakeTLS: неожиданная запись %d", i)
		}
		resp = append(resp, rec...)
	}
	if len(resp) < 43 {
		c.Close()
		return nil, errors.New("FakeTLS: короткий ответ")
	}
	got := append([]byte{}, resp[11:43]...)
	for i := 11; i < 43; i++ {
		resp[i] = 0
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(hello[11:43])
	mac.Write(resp)
	if !hmac.Equal(mac.Sum(nil), got) {
		c.Close()
		return nil, errors.New("FakeTLS: прокси не подтвердил секрет")
	}
	c.SetDeadline(time.Time{})
	return &fakeTLSConn{Conn: c}, nil
}

// fakeTLSConn упаковывает поток в записи TLS application data.
type fakeTLSConn struct {
	net.Conn
	wmu    sync.Mutex
	sentCC bool
	rbuf   []byte
}

func (f *fakeTLSConn) Write(b []byte) (int, error) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	var out []byte
	if !f.sentCC {
		out = append(out, 0x14, 3, 3, 0, 1, 1)
		f.sentCC = true
	}
	for off := 0; off < len(b); {
		n := len(b) - off
		if n > 16384 {
			n = 16384
		}
		out = append(out, 0x17, 3, 3, byte(n>>8), byte(n))
		out = append(out, b[off:off+n]...)
		off += n
	}
	if _, err := f.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (f *fakeTLSConn) Read(b []byte) (int, error) {
	for len(f.rbuf) == 0 {
		typ, rec, err := readTLSRecord(f.Conn)
		if err != nil {
			return 0, err
		}
		switch typ {
		case 0x17:
			f.rbuf = rec[5:]
		case 0x14:
		default:
			return 0, errors.New("FakeTLS: прокси закрыл соединение")
		}
	}
	n := copy(b, f.rbuf)
	f.rbuf = f.rbuf[n:]
	return n, nil
}
