package tg

// Локальный MTProto-прокси для Telegram Desktop.
// Telegram подключается к 127.0.0.1 как к обычному MTProto-прокси, а мы
// переупаковываем его трафик в WebSocket к kwsN.web.telegram.org (так работает
// web-версия Telegram). Такой трафик выглядит как обычный HTTPS к сайту
// Telegram, и его можно пропустить через обход DPI. Идея - проект
// Flowseal/tg-ws-proxy (MIT), здесь своя реализация на Go.

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tgHandshakeLen = 64
	tgSkipLen      = 8
	tgPrekeyLen    = 32
	tgIVLen        = 16
	tgTagPos       = 56
	tgDCPos        = 60
	tgWSFallbackIP = "149.154.167.220"
)

var (
	tagAbridged     = []byte{0xef, 0xef, 0xef, 0xef}
	tagIntermediate = []byte{0xee, 0xee, 0xee, 0xee}
	tagSecure       = []byte{0xdd, 0xdd, 0xdd, 0xdd}

	tgDCIPs = map[int]string{
		1: "149.154.175.50", 2: "149.154.167.51", 3: "149.154.175.100",
		4: "149.154.167.91", 5: "149.154.171.5", 203: "91.105.192.100",
	}
)

// ---------- криптография obfuscated2 ----------

func ctrStream(key, iv []byte) cipher.Stream {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return cipher.NewCTR(b, iv)
}

func xorBytes(s cipher.Stream, in []byte) []byte {
	out := make([]byte, len(in))
	s.XORKeyStream(out, in)
	return out
}

func reversed(b []byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return r
}

func withSecret(prekey, secret []byte) []byte {
	h := sha256.Sum256(append(append([]byte{}, prekey...), secret...))
	return h[:]
}

type tgClientInit struct {
	DC    int
	Media bool
	Test  bool
	Tag   []byte
}

// parseClientInit расшифровывает 64-байтное приветствие Telegram Desktop.
func parseClientInit(init, secret []byte) (tgClientInit, bool) {
	var r tgClientInit
	if len(init) != tgHandshakeLen {
		return r, false
	}
	key := withSecret(init[tgSkipLen:tgSkipLen+tgPrekeyLen], secret)
	iv := init[tgSkipLen+tgPrekeyLen : tgSkipLen+tgPrekeyLen+tgIVLen]
	dec := xorBytes(ctrStream(key, iv), init)
	tag := dec[tgTagPos : tgTagPos+4]
	if !bytesEq(tag, tagAbridged) && !bytesEq(tag, tagIntermediate) && !bytesEq(tag, tagSecure) {
		return r, false
	}
	idx := int(int16(binary.LittleEndian.Uint16(dec[tgDCPos : tgDCPos+2])))
	r.Tag = append([]byte{}, tag...)
	if idx < 0 {
		r.Media, idx = true, -idx
	}
	if idx >= 10000 {
		r.Test, idx = true, idx-10000
	}
	r.DC = idx
	return r, r.DC > 0
}

func bytesEq(a, b []byte) bool { return string(a) == string(b) }

// relayKey - ключ obfuscated2 к следующему звену: для серверов Telegram ключ берётся
// как есть, для внешнего MTProto-прокси он смешивается с его секретом.
func relayKey(prekey, secret []byte) []byte {
	if secret == nil {
		return prekey
	}
	return withSecret(prekey, secret)
}

// newRelayInit создаёт приветствие для серверов Telegram (обычный obfuscated2 без секрета)
// или для внешнего MTProto-прокси (secret - его 16-байтный ключ).
func newRelayInit(tag []byte, dcIdx int16, secret ...[]byte) []byte {
	var sec []byte
	if len(secret) > 0 {
		sec = secret[0]
	}
	rnd := make([]byte, tgHandshakeLen)
	for {
		rand.Read(rnd)
		if rnd[0] == 0xef {
			continue
		}
		switch string(rnd[:4]) {
		case "HEAD", "POST", "GET ", "\xee\xee\xee\xee", "\xdd\xdd\xdd\xdd", "\x16\x03\x01\x02", "OPTI":
			continue
		}
		if binary.LittleEndian.Uint32(rnd[4:8]) == 0 {
			continue
		}
		break
	}
	key := relayKey(rnd[tgSkipLen:tgSkipLen+tgPrekeyLen], sec)
	iv := rnd[tgSkipLen+tgPrekeyLen : tgSkipLen+tgPrekeyLen+tgIVLen]
	enc := xorBytes(ctrStream(key, iv), rnd)

	tail := make([]byte, 8)
	copy(tail, tag)
	binary.LittleEndian.PutUint16(tail[4:6], uint16(dcIdx))
	rand.Read(tail[6:8])

	out := append([]byte{}, rnd...)
	for i := 0; i < 8; i++ {
		out[tgTagPos+i] = tail[i] ^ (enc[tgTagPos+i] ^ rnd[tgTagPos+i])
	}
	return out
}

type tgCrypto struct {
	cltDec, cltEnc, tgEnc, tgDec cipher.Stream
}

func newTGCrypto(clientInit, secret, relayInit []byte, relaySecret ...[]byte) *tgCrypto {
	var rs []byte
	if len(relaySecret) > 0 {
		rs = relaySecret[0]
	}
	c := &tgCrypto{}
	pk := clientInit[tgSkipLen : tgSkipLen+tgPrekeyLen+tgIVLen]
	c.cltDec = ctrStream(withSecret(pk[:tgPrekeyLen], secret), pk[tgPrekeyLen:])
	c.cltDec.XORKeyStream(make([]byte, 64), make([]byte, 64)) // пропустить приветствие
	rpk := reversed(pk)
	c.cltEnc = ctrStream(withSecret(rpk[:tgPrekeyLen], secret), rpk[tgPrekeyLen:])

	tk := relayInit[tgSkipLen : tgSkipLen+tgPrekeyLen+tgIVLen]
	c.tgEnc = ctrStream(relayKey(tk[:tgPrekeyLen], rs), tk[tgPrekeyLen:])
	c.tgEnc.XORKeyStream(make([]byte, 64), make([]byte, 64))
	rtk := reversed(tk)
	c.tgDec = ctrStream(relayKey(rtk[:tgPrekeyLen], rs), rtk[tgPrekeyLen:])
	return c
}

// ---------- разбиение потока на пакеты MTProto (1 пакет = 1 сообщение WebSocket) ----------

type msgSplitter struct {
	abridged bool
	cipher   []byte
	plain    []byte
	disabled bool
}

func newSplitter(tag []byte) *msgSplitter {
	return &msgSplitter{abridged: bytesEq(tag, tagAbridged)}
}

func (s *msgSplitter) split(enc, plain []byte) [][]byte {
	if s.disabled {
		return [][]byte{enc}
	}
	s.cipher = append(s.cipher, enc...)
	s.plain = append(s.plain, plain...)
	var parts [][]byte
	off := 0
	for off < len(s.cipher) {
		n := s.nextLen(off)
		if n < 0 {
			break // пакет пришёл не целиком
		}
		if n == 0 { // непонятный формат - дальше шлём как есть
			parts = append(parts, append([]byte{}, s.cipher[off:]...))
			off = len(s.cipher)
			s.disabled = true
			break
		}
		parts = append(parts, append([]byte{}, s.cipher[off:off+n]...))
		off += n
	}
	s.cipher = append([]byte{}, s.cipher[off:]...)
	s.plain = append([]byte{}, s.plain[off:]...)
	return parts
}

func (s *msgSplitter) flush() []byte {
	b := s.cipher
	s.cipher, s.plain = nil, nil
	return b
}

// nextLen: >0 длина пакета, -1 нужно больше данных, 0 формат не распознан
func (s *msgSplitter) nextLen(off int) int {
	avail := len(s.plain) - off
	p := s.plain[off:]
	var hdr, payload int
	if s.abridged {
		if p[0] == 0x7f || p[0] == 0xff {
			if avail < 4 {
				return -1
			}
			payload = int(uint32(p[1])|uint32(p[2])<<8|uint32(p[3])<<16) * 4
			hdr = 4
		} else {
			payload = int(p[0]&0x7f) * 4
			hdr = 1
		}
	} else {
		if avail < 4 {
			return -1
		}
		payload = int(binary.LittleEndian.Uint32(p[:4]) & 0x7fffffff)
		hdr = 4
	}
	if payload <= 0 {
		return 0
	}
	if avail < hdr+payload {
		return -1
	}
	return hdr + payload
}

// ---------- минимальный WebSocket ----------

type wsConn struct {
	c   net.Conn
	br  *bufio.Reader
	wmu sync.Mutex
	// mask - клиент обязан маскировать кадры (сервер - нет)
	mask bool
}

type wsHandshakeErr struct{ Status string }

func (e wsHandshakeErr) Error() string { return "WebSocket: " + e.Status }

func wsClientHandshake(c net.Conn, host, path string) (*wsConn, error) {
	key := make([]byte, 16)
	rand.Read(key)
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: binary\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(c, 64<<10)
	status, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	f := strings.Fields(status)
	if len(f) < 2 || f[1] != "101" {
		return nil, wsHandshakeErr{strings.TrimSpace(status)}
	}
	return &wsConn{c: c, br: br, mask: true}, nil
}

func (w *wsConn) writeFrame(op byte, data []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	hdr := []byte{0x80 | op}
	mbit := byte(0)
	if w.mask {
		mbit = 0x80
	}
	switch n := len(data); {
	case n < 126:
		hdr = append(hdr, mbit|byte(n))
	case n <= 0xffff:
		hdr = append(hdr, mbit|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, mbit|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	payload := data
	if w.mask {
		m := make([]byte, 4)
		rand.Read(m)
		hdr = append(hdr, m...)
		payload = make([]byte, len(data))
		for i := range data {
			payload[i] = data[i] ^ m[i&3]
		}
	}
	_, err := w.c.Write(append(hdr, payload...))
	return err
}

func (w *wsConn) WriteMsg(data []byte) error { return w.writeFrame(0x2, data) }

func (w *wsConn) ReadMsg() ([]byte, error) {
	var msg []byte
	for {
		h := make([]byte, 2)
		if _, err := io.ReadFull(w.br, h); err != nil {
			return nil, err
		}
		fin, op := h[0]&0x80 != 0, h[0]&0x0f
		masked := h[1]&0x80 != 0
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			b := make([]byte, 2)
			if _, err := io.ReadFull(w.br, b); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b))
		case 127:
			b := make([]byte, 8)
			if _, err := io.ReadFull(w.br, b); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(b)
		}
		if n > 16<<20 {
			return nil, errors.New("WebSocket: слишком большой кадр")
		}
		var m []byte
		if masked {
			m = make([]byte, 4)
			if _, err := io.ReadFull(w.br, m); err != nil {
				return nil, err
			}
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(w.br, p); err != nil {
			return nil, err
		}
		if masked {
			for i := range p {
				p[i] ^= m[i&3]
			}
		}
		switch op {
		case 0x8: // close
			w.writeFrame(0x8, nil)
			return nil, io.EOF
		case 0x9: // ping
			w.writeFrame(0xA, p)
			continue
		case 0xA: // pong
			continue
		}
		msg = append(msg, p...)
		if fin {
			return msg, nil
		}
	}
}

func (w *wsConn) Close() error { return w.c.Close() }

// ---------- сам прокси ----------

// TGRoute - один из способов достучаться до серверов Telegram.
// Заполняется либо WS (сообщения WebSocket), либо TCP (сырой поток obfuscated2).
type TGRoute struct {
	Name string
	WS   func(dc int, media, test bool) (*wsConn, string, error)
	TCP  func(dc int) (net.Conn, string, error)
	// RelaySecret - ключ внешнего MTProto-прокси (для TCP); nil - серверы Telegram напрямую
	RelaySecret []byte
}

type TGProxy struct {
	Secret  []byte
	Resolve func(host string) net.IP // адрес домена (nil - системный DNS)
	DialWS  func(dc int, media, test bool) (*wsConn, string, error)
	DialTCP func(dc int) (net.Conn, error)
	// Routes - способы по порядку; nil = WebSocket напрямую, потом TCP напрямую.
	// Функция, чтобы маршруты могли меняться на ходу (VPN включили/выключили).
	Routes func() []TGRoute
	Log    func(format string, a ...any)

	badMu    sync.Mutex
	badUntil map[string]time.Time
	allFail  atomic.Int64

	ln      net.Listener
	active  atomic.Int64
	total   atomic.Int64
	viaWS   atomic.Int64
	viaTCP  atomic.Int64
	failed  atomic.Int64
	seenMu  sync.Mutex
	seenKey map[string]bool

	routeMu   sync.Mutex
	routeStat map[string]*[2]int64 // способ -> [удачно, неудачно]
}

func (p *TGProxy) countRoute(name string, ok bool) {
	p.routeMu.Lock()
	defer p.routeMu.Unlock()
	if p.routeStat == nil {
		p.routeStat = map[string]*[2]int64{}
	}
	st := p.routeStat[name]
	if st == nil {
		st = &[2]int64{}
		p.routeStat[name] = st
	}
	if ok {
		st[0]++
	} else {
		st[1]++
	}
}

// RouteStats - сколько раз каждый способ сработал и не сработал
func (p *TGProxy) RouteStats() map[string][2]int64 {
	p.routeMu.Lock()
	defer p.routeMu.Unlock()
	out := map[string][2]int64{}
	for k, v := range p.routeStat {
		out[k] = *v
	}
	return out
}

func (p *TGProxy) logf(format string, a ...any) {
	if p.Log != nil {
		p.Log(format, a...)
	}
}

// logOnce пишет сообщение только при первом появлении (чтобы не засорять терминал)
func (p *TGProxy) logOnce(key, format string, a ...any) {
	p.seenMu.Lock()
	if p.seenKey == nil {
		p.seenKey = map[string]bool{}
	}
	seen := p.seenKey[key]
	p.seenKey[key] = true
	p.seenMu.Unlock()
	if !seen {
		p.logf(format, a...)
	}
}

func (p *TGProxy) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(c)
		}
	}()
	return nil
}

func (p *TGProxy) Addr() string { return p.ln.Addr().String() }
func (p *TGProxy) Close()       { p.ln.Close() }

func (p *TGProxy) Stats() (active, total, ws, tcp, failed int64) {
	return p.active.Load(), p.total.Load(), p.viaWS.Load(), p.viaTCP.Load(), p.failed.Load()
}

func tgWSDomains(dc int, media bool) []string {
	if dc == 203 {
		dc = 2
	}
	d := fmt.Sprintf("kws%d.web.telegram.org", dc)
	if media {
		return []string{fmt.Sprintf("kws%d-1.web.telegram.org", dc), d}
	}
	return []string{d}
}

// dialWSS открывает wss://host/path. dial - как установить TCP-соединение.
func dialWSS(host, ip, path string, dial func(addr string) (net.Conn, error)) (*wsConn, error) {
	raw, err := dial(net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	tc := tls.Client(raw, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	ws, err := wsClientHandshake(tc, host, path)
	if err != nil {
		tc.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return ws, nil
}

func directDial(addr string) (net.Conn, error) { return net.DialTimeout("tcp", addr, 6*time.Second) }

func (p *TGProxy) resolveOr(host, def string) string {
	if p.Resolve != nil {
		if r := p.Resolve(host); r != nil {
			return r.String()
		}
	}
	return def
}

func tgPath(test bool) string {
	if test {
		return "/apiws_test"
	}
	return "/apiws"
}

func (p *TGProxy) defaultDialWS(dc int, media, test bool) (*wsConn, string, error) {
	return p.dialWSVia(dc, media, test, directDial)
}

// wsIPs - адреса для домена kws: найденный через DNS и запасной (если отличается)
func (p *TGProxy) wsIPs(host string) []string {
	ip := p.resolveOr(host, tgWSFallbackIP)
	if ip == tgWSFallbackIP {
		return []string{ip}
	}
	return []string{ip, tgWSFallbackIP}
}

func (p *TGProxy) dialWSVia(dc int, media, test bool, dial func(addr string) (net.Conn, error)) (*wsConn, string, error) {
	var lastErr error
	for _, host := range tgWSDomains(dc, media) {
		for _, ip := range p.wsIPs(host) {
			ws, err := dialWSS(host, ip, tgPath(test), dial)
			if err == nil {
				return ws, host, nil
			}
			lastErr = err
			var he wsHandshakeErr
			if errors.As(err, &he) {
				break // сервер ответил, но не пустил - другой IP того же домена не поможет
			}
		}
	}
	return nil, "", lastErr
}

// WSSocksRoute - WebSocket к web.telegram.org через локальный SOCKS5
// (на Android - через byedpi, который маскирует TLS от DPI).
func (p *TGProxy) WSSocksRoute(name, socksAddr string) TGRoute {
	return TGRoute{Name: name, WS: func(dc int, media, test bool) (*wsConn, string, error) {
		return p.dialWSVia(dc, media, test, func(addr string) (net.Conn, error) { return socks5Dial(socksAddr, addr) })
	}}
}

func tgDCAddr(dc int) string {
	ip, ok := tgDCIPs[dc]
	if !ok {
		ip = tgDCIPs[2]
	}
	return net.JoinHostPort(ip, "443")
}

func (p *TGProxy) defaultDialTCP(dc int) (net.Conn, error) { return directDial(tgDCAddr(dc)) }

// WorkerRoute - WebSocket через свой Cloudflare Worker (если IP Telegram заблокированы).
func (p *TGProxy) WorkerRoute(host string) TGRoute {
	return TGRoute{Name: "Cloudflare Worker", WS: func(dc int, media, test bool) (*wsConn, string, error) {
		m, t := 0, 0
		if media {
			m = 1
		}
		if test {
			t = 1
		}
		path := fmt.Sprintf("/apiws?dc=%d&media=%d&test=%d", dc, m, t)
		ws, err := dialWSS(host, p.resolveOr(host, host), path, directDial)
		return ws, host, err
	}}
}

// SocksRoute - сырой MTProto через локальный SOCKS5 VPN-клиента (Happ и т.п.).
func SocksRoute(name, socksAddr string) TGRoute {
	return TGRoute{Name: name, TCP: func(dc int) (net.Conn, string, error) {
		c, err := socks5Dial(socksAddr, tgDCAddr(dc))
		return c, socksAddr, err
	}}
}

func socks5Dial(proxy, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fail := func(e error) (net.Conn, error) { c.Close(); return nil, e }
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[0] != 5 || r[1] != 0 {
		return fail(errors.New("SOCKS5: прокси не принял подключение"))
	}
	host, portS, _ := net.SplitHostPort(target)
	var port int
	fmt.Sscanf(portS, "%d", &port)
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host).To4(); ip != nil {
		req = append(append(req, 1), ip...)
	} else {
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return fail(err)
	}
	if h[1] != 0 {
		return fail(fmt.Errorf("SOCKS5: ошибка %d", h[1]))
	}
	skip := 0
	switch h[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return fail(err)
		}
		skip = int(l[0])
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		return fail(err)
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

// IsSocks5 - отвечает ли адрес как SOCKS5 без пароля
func IsSocks5(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return false
	}
	r := make([]byte, 2)
	_, err = io.ReadFull(c, r)
	return err == nil && r[0] == 5 && r[1] == 0
}

func (p *TGProxy) routes() []TGRoute {
	if p.Routes != nil {
		return p.Routes()
	}
	return p.BaseRoutes()
}

// BaseRoutes - WebSocket напрямую, затем TCP напрямую
func (p *TGProxy) BaseRoutes() []TGRoute {
	ws := p.DialWS
	if ws == nil {
		ws = p.defaultDialWS
	}
	tcp := p.DialTCP
	if tcp == nil {
		tcp = p.defaultDialTCP
	}
	return []TGRoute{
		{Name: "WebSocket", WS: ws},
		{Name: "напрямую", TCP: func(dc int) (net.Conn, string, error) {
			c, err := tcp(dc)
			return c, "", err
		}},
	}
}

func (p *TGProxy) isBad(key string) bool {
	p.badMu.Lock()
	defer p.badMu.Unlock()
	return time.Now().Before(p.badUntil[key])
}

func (p *TGProxy) setBad(key string, bad bool) {
	p.badMu.Lock()
	defer p.badMu.Unlock()
	if p.badUntil == nil {
		p.badUntil = map[string]time.Time{}
	}
	if bad {
		p.badUntil[key] = time.Now().Add(3 * time.Minute)
	} else {
		delete(p.badUntil, key)
	}
}

// AllFailed - сколько соединений не удалось провести ни одним способом
func (p *TGProxy) AllFailed() int64 { return p.allFail.Load() }

func (p *TGProxy) handle(c net.Conn) {
	p.total.Add(1)
	p.active.Add(1)
	defer p.active.Add(-1)
	defer c.Close()

	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	init := make([]byte, tgHandshakeLen)
	if _, err := io.ReadFull(c, init); err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	ci, ok := parseClientInit(init, p.Secret)
	if !ok {
		p.failed.Add(1)
		p.logOnce("badsecret", "Telegram: неверное приветствие - добавь прокси заново по ссылке из этого окна")
		return
	}
	dcIdx := ci.DC
	if ci.Test {
		dcIdx += 10000
	}
	if ci.Media {
		dcIdx = -dcIdx
	}
	relay := newRelayInit(ci.Tag, int16(dcIdx))
	cr := newTGCrypto(init, p.Secret, relay)
	// для внешнего MTProto-прокси приветствие и ключи другие (смешаны с его секретом)
	relayFor := func(r TGRoute) ([]byte, *tgCrypto) {
		if r.RelaySecret == nil {
			return relay, cr
		}
		ri := newRelayInit(ci.Tag, int16(dcIdx), r.RelaySecret)
		return ri, newTGCrypto(init, p.Secret, ri, r.RelaySecret)
	}
	label := fmt.Sprintf("DC%d", ci.DC)
	if ci.Media {
		label += " (медиа)"
	}

	routes := p.routes()
	tried := 0
	for pass := 0; pass < 2 && tried == 0; pass++ {
		for _, r := range routes {
			key := fmt.Sprintf("%s/%d/%v", r.Name, ci.DC, ci.Media)
			// недавно сломанные способы пропускаем (если сломано всё - второй проход пробует всё)
			if pass == 0 && p.isBad(key) {
				continue
			}
			tried++
			if r.WS != nil {
				ws, host, err := r.WS(ci.DC, ci.Media, ci.Test)
				if err != nil {
					p.setBad(key, true)
					p.countRoute(r.Name, false)
					p.logOnce("fail"+key, "Telegram %s: %s не работает (%s)", label, r.Name, shortErrMsg(err))
					continue
				}
				p.setBad(key, false)
				p.countRoute(r.Name, true)
				p.viaWS.Add(1)
				p.logOnce("ok"+key, "Telegram %s -> %s %s", label, r.Name, host)
				if err := ws.WriteMsg(relay); err != nil {
					ws.Close()
					return
				}
				p.bridgeWS(c, ws, cr, newSplitter(ci.Tag))
				return
			}
			tc, via, err := r.TCP(ci.DC)
			if err != nil {
				p.setBad(key, true)
				p.countRoute(r.Name, false)
				p.logOnce("fail"+key, "Telegram %s: %s не работает (%s)", label, r.Name, shortErrMsg(err))
				continue
			}
			p.setBad(key, false)
			p.countRoute(r.Name, true)
			p.viaTCP.Add(1)
			p.logOnce("ok"+key, "Telegram %s -> %s %s", label, r.Name, via)
			ri, rc := relayFor(r)
			if _, err := tc.Write(ri); err != nil {
				tc.Close()
				return
			}
			p.bridgeTCP(c, tc, rc)
			tc.Close()
			return
		}
	}
	p.failed.Add(1)
	p.allFail.Add(1)
}

func shortErrMsg(err error) string {
	if err == nil {
		return "нет ответа"
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		s = s[i+2:]
	}
	return s
}

func (p *TGProxy) bridgeWS(c net.Conn, ws *wsConn, cr *tgCrypto, sp *msgSplitter) {
	defer ws.Close()
	done := make(chan struct{}, 2)
	go func() { // Telegram Desktop -> WebSocket
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 64<<10)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				plain := xorBytes(cr.cltDec, buf[:n])
				enc := xorBytes(cr.tgEnc, plain)
				for _, part := range sp.split(enc, plain) {
					if ws.WriteMsg(part) != nil {
						return
					}
				}
			}
			if err != nil {
				if t := sp.flush(); len(t) > 0 {
					ws.WriteMsg(t)
				}
				return
			}
		}
	}()
	go func() { // WebSocket -> Telegram Desktop
		defer func() { done <- struct{}{} }()
		for {
			m, err := ws.ReadMsg()
			if err != nil {
				return
			}
			out := xorBytes(cr.cltEnc, xorBytes(cr.tgDec, m))
			if _, err := c.Write(out); err != nil {
				return
			}
		}
	}()
	<-done
}

func (p *TGProxy) bridgeTCP(c, tc net.Conn, cr *tgCrypto) {
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn, a, b cipher.Stream) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 64<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(xorBytes(b, xorBytes(a, buf[:n]))); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go pipe(tc, c, cr.cltDec, cr.tgEnc)
	go pipe(c, tc, cr.tgDec, cr.cltEnc)
	<-done
}
