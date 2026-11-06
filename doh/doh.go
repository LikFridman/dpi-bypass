// Package doh - зашифрованный DNS (DNS-over-HTTPS) для обхода подмены DNS провайдером.
//
// Запросы уходят по HTTPS прямо на IP-адреса Cloudflare, Google и Quad9 (без предварительного
// обычного DNS-запроса, который провайдер мог бы подменить). Ответы кешируются по TTL.
// Используется: маршрутизатором на Android (UDP 53 из туннеля), локальным DNS-сервером на Windows
// и проверками сайтов (Ping all, подбор), чтобы они видели то же, что браузер.
package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Endpoints - серверы DoH по IP (у сертификатов есть эти IP, поэтому начальный DNS не нужен)
var Endpoints = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
	"https://1.0.0.1/dns-query",
	"https://9.9.9.9/dns-query",
	"https://8.8.4.4/dns-query",
}

// Dial - как соединяться с сервером DoH
type Dial func(ctx context.Context, network, addr string) (net.Conn, error)

// Resolver - клиент DoH с кешем
type Resolver struct {
	clients   []*http.Client // [напрямую, через запасной путь]
	endpoints []string
	primary   bool // первый сервер выбран пользователем: к запасным - только если он молчит

	mu    sync.Mutex
	cache map[string]cacheEntry
	good  int // индекс сервера, который отвечал последним

	Stats struct {
		sync.Mutex
		Queries, CacheHits, Failures int64
		LastError                    string
	}
}

type cacheEntry struct {
	msg []byte
	exp time.Time
}

// New - резолвер (серверы из Endpoints); dial - основной путь (nil - напрямую), fallback - запасной
// (например, через byedpi), может быть nil
func New(dial, fallback Dial) *Resolver { return newResolver(Endpoints, dial, fallback, nil) }

func newResolver(endpoints []string, dial, fallback Dial, boot map[string][]string) *Resolver {
	r := &Resolver{cache: map[string]cacheEntry{}, endpoints: append([]string{}, endpoints...)}
	for _, d := range []Dial{dial, fallback} {
		if d == nil && len(r.clients) > 0 {
			continue
		}
		if d == nil {
			d = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
		}
		if len(boot) > 0 {
			d = bootDial(d, boot)
		}
		tr := &http.Transport{
			DialContext:         d,
			TLSHandshakeTimeout: 5 * time.Second,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: testRoots},
		}
		r.clients = append(r.clients, &http.Client{Transport: tr, Timeout: 6 * time.Second})
	}
	return r
}

// для тестов: свой корневой сертификат
var testRoots *x509.CertPool

// ---------- запросы ----------

// Exchange отправляет DNS-сообщение (как в UDP) и возвращает ответ с тем же ID
func (r *Resolver) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	if len(q) < 12 {
		return nil, errors.New("короткий DNS-запрос")
	}
	key, ok := questionKey(q)
	r.Stats.Lock()
	r.Stats.Queries++
	r.Stats.Unlock()
	if ok {
		r.mu.Lock()
		e, hit := r.cache[key]
		r.mu.Unlock()
		if hit && time.Now().Before(e.exp) {
			r.Stats.Lock()
			r.Stats.CacheHits++
			r.Stats.Unlock()
			out := append([]byte{}, e.msg...)
			copy(out[:2], q[:2])
			return out, nil
		}
	}
	// ID в DoH принято ставить 0 (лучше кешируется у сервера); вернём исходный
	wire := append([]byte{}, q...)
	wire[0], wire[1] = 0, 0
	var lastErr error
	for _, cl := range r.clients {
		resp, err := r.race(ctx, cl, wire)
		if err == nil {
			if ok {
				ttl := minTTL(resp)
				r.mu.Lock()
				if len(r.cache) > 4096 {
					r.cache = map[string]cacheEntry{}
				}
				r.cache[key] = cacheEntry{msg: resp, exp: time.Now().Add(ttl)}
				r.mu.Unlock()
			}
			out := append([]byte{}, resp...)
			copy(out[:2], q[:2])
			return out, nil
		}
		lastErr = err
	}
	r.Stats.Lock()
	r.Stats.Failures++
	r.Stats.LastError = lastErr.Error()
	r.Stats.Unlock()
	return nil, lastErr
}

// race: сначала сервер, который отвечал последним; если он молчит 700 мс - параллельно следующий
func (r *Resolver) race(ctx context.Context, cl *http.Client, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	type res struct {
		i   int
		b   []byte
		err error
	}
	r.mu.Lock()
	start := r.good
	if r.primary {
		start = 0 // выбранный пользователем сервер - всегда первым
	}
	r.mu.Unlock()
	eps := r.endpoints
	ch := make(chan res, len(eps))
	launched := 0
	launch := func() {
		i := (start + launched) % len(eps)
		launched++
		go func() {
			b, err := post(ctx, cl, eps[i], q)
			ch <- res{i, b, err}
		}()
	}
	launch()
	var errs []string
	step := 700 * time.Millisecond
	if r.primary {
		step = 2500 * time.Millisecond
	}
	tick := time.NewTicker(step)
	defer tick.Stop()
	for done := 0; done < len(eps); {
		select {
		case x := <-ch:
			done++
			if x.err == nil {
				r.mu.Lock()
				r.good = x.i
				r.mu.Unlock()
				return x.b, nil
			}
			errs = append(errs, x.err.Error())
			if launched < len(eps) {
				launch()
			} else if done >= launched {
				return nil, fmt.Errorf("DoH: %s", strings.Join(errs, "; "))
			}
		case <-tick.C:
			if launched < len(eps) {
				launch()
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("DoH: нет ответа (%s)", strings.Join(errs, "; "))
		}
	}
	return nil, fmt.Errorf("DoH: %s", strings.Join(errs, "; "))
}

func post(ctx context.Context, cl *http.Client, url string, q []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	if len(b) < 12 {
		return nil, fmt.Errorf("%s: пустой ответ", url)
	}
	return b, nil
}

// ---------- разбор DNS ----------

// questionKey - ключ кеша: вопрос (имя без учёта регистра, тип, класс)
func questionKey(q []byte) (string, bool) {
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		return "", false
	}
	end, ok := skipName(q, 12)
	if !ok || end+4 > len(q) {
		return "", false
	}
	return strings.ToLower(string(q[12:end])) + string(q[end:end+4]), true
}

func skipName(b []byte, off int) (int, bool) {
	for n := 0; n < 128; n++ {
		if off >= len(b) {
			return 0, false
		}
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1, true
		case l&0xC0 == 0xC0:
			return off + 2, off+2 <= len(b)
		default:
			off += 1 + l
		}
	}
	return 0, false
}

// minTTL - наименьший TTL записей ответа (от 30 с до 10 мин; для пустых ответов - 60 с)
func minTTL(m []byte) time.Duration {
	const lo, hi = 30, 600
	if len(m) < 12 {
		return lo * time.Second
	}
	qd, an := int(binary.BigEndian.Uint16(m[4:6])), int(binary.BigEndian.Uint16(m[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		e, ok := skipName(m, off)
		if !ok {
			return lo * time.Second
		}
		off = e + 4
	}
	ttl := uint32(hi)
	if an == 0 || m[3]&0x0F != 0 {
		return 60 * time.Second
	}
	for i := 0; i < an; i++ {
		e, ok := skipName(m, off)
		if !ok || e+10 > len(m) {
			break
		}
		t := binary.BigEndian.Uint32(m[e+4 : e+8])
		if t < ttl {
			ttl = t
		}
		off = e + 10 + int(binary.BigEndian.Uint16(m[e+8:e+10]))
	}
	if ttl < lo {
		ttl = lo
	}
	return time.Duration(ttl) * time.Second
}

// BuildQuery - DNS-запрос типа t (1 = A, 28 = AAAA)
func BuildQuery(name string, t uint16) []byte {
	b := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, p := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if p == "" || len(p) > 63 {
			continue
		}
		b = append(b, byte(len(p)))
		b = append(b, p...)
	}
	b = append(b, 0, byte(t>>8), byte(t), 0, 1)
	return b
}

// ParseIPs - адреса из ответа (A и AAAA)
func ParseIPs(m []byte) []net.IP {
	if len(m) < 12 {
		return nil
	}
	qd, an := int(binary.BigEndian.Uint16(m[4:6])), int(binary.BigEndian.Uint16(m[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		e, ok := skipName(m, off)
		if !ok {
			return nil
		}
		off = e + 4
	}
	var out []net.IP
	for i := 0; i < an; i++ {
		e, ok := skipName(m, off)
		if !ok || e+10 > len(m) {
			break
		}
		t := binary.BigEndian.Uint16(m[e : e+2])
		l := int(binary.BigEndian.Uint16(m[e+8 : e+10]))
		d := e + 10
		if d+l > len(m) {
			break
		}
		if (t == 1 && l == 4) || (t == 28 && l == 16) {
			out = append(out, net.IP(append([]byte{}, m[d:d+l]...)))
		}
		off = d + l
	}
	return out
}

// LookupIP - адреса имени через DoH (сначала A, при пустом ответе - AAAA)
func (r *Resolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	for _, t := range []uint16{1, 28} {
		m, err := r.Exchange(ctx, BuildQuery(host, t))
		if err != nil {
			return nil, err
		}
		if ips := ParseIPs(m); len(ips) > 0 {
			return ips, nil
		}
	}
	return nil, &net.DNSError{Err: "нет адресов (DoH)", Name: host, IsNotFound: true}
}

// Wrap - соединение с разрешением имени через DoH; если DoH недоступен - как было (обычный DNS)
func (r *Resolver) Wrap(base Dial) Dial {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || net.ParseIP(host) != nil {
			return base(ctx, network, addr)
		}
		ips, err := r.LookupIP(ctx, host)
		if err != nil {
			var de *net.DNSError
			if errors.As(err, &de) {
				return nil, de
			}
			return base(ctx, network, addr) // DoH недоступен - обычный DNS
		}
		var lastErr error
		for i, ip := range ips {
			if i >= 2 {
				break
			}
			c, err := base(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return c, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

// ---------- локальный DNS-сервер (Windows) ----------

// ServeUDP отвечает на DNS-запросы через DoH, пока pc не закрыт
func (r *Resolver) ServeUDP(pc net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte{}, buf[:n]...)
		go func() {
			if resp, err := r.Exchange(context.Background(), q); err == nil {
				pc.WriteTo(resp, from)
			} else if len(q) >= 12 {
				pc.WriteTo(servfail(q), from)
			}
		}()
	}
}

// ServeTCP - то же по TCP (длина сообщения - 2 байта впереди)
func (r *Resolver) ServeTCP(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			for {
				c.SetDeadline(time.Now().Add(20 * time.Second))
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, q); err != nil || len(q) < 12 {
					return
				}
				resp, err := r.Exchange(context.Background(), q)
				if err != nil {
					resp = servfail(q)
				}
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				copy(out[2:], resp)
				if _, err := c.Write(out); err != nil {
					return
				}
			}
		}(c)
	}
}

// QuestionEnd - конец секции вопроса (0 - не разобрать)
func QuestionEnd(q []byte) int {
	if e, ok := skipName(q, 12); ok && e+4 <= len(q) {
		return e + 4
	}
	return 0
}

func servfail(q []byte) []byte {
	end := len(q)
	if e, ok := skipName(q, 12); ok && e+4 <= len(q) {
		end = e + 4
	}
	out := append([]byte{}, q[:end]...)
	out[2] = 0x81 | (q[2] & 0x01) // QR=1, RD как в запросе
	out[3] = 0x82                 // RA=1, RCODE=SERVFAIL
	binary.BigEndian.PutUint16(out[6:], 0)
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	return out
}
