// Package router - локальный SOCKS5-маршрутизатор для Android: стоит между
// VPN-туннелем (hev-socks5-tunnel) и byedpi и решает, куда отправить соединение:
//   - TCP: по имени сайта (SNI/Host) - в копию byedpi со стратегией для этого сайта;
//   - соединения приложения Telegram к его серверам - напрямую через byedpi или,
//     если они не проходят, прозрачно через WebSocket к web.telegram.org;
//   - UDP 443 (QUIC) - отбрасывается, чтобы YouTube и браузеры перешли на TCP,
//     где работает обход;
//   - UDP голоса Discord - через byedpi с фейковыми UDP-пакетами;
//   - остальной UDP (DNS и т.п.) - напрямую.
package router

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"context"
	"dpibypass/doh"
	"dpibypass/tg"
)

// Group - копия byedpi со своей стратегией для списка доменов.
type Group struct {
	Upstream string   `json:"upstream"` // 127.0.0.1:1081; "direct" - без обхода
	Domains  []string `json:"domains"`
}

// Config - настройки маршрутизатора (передаются JSON-файлом).
type Config struct {
	Listen       string   `json:"listen"`        // 127.0.0.1:1090
	Default      string   `json:"default"`       // byedpi для всего остального
	Groups       []Group  `json:"groups"`        // стратегии по сайтам
	BlockQUIC    bool     `json:"block_quic"`    // отбрасывать UDP 443
	UDPUpstream  string   `json:"udp_upstream"`  // byedpi для UDP голоса ("" - напрямую)
	UDPPorts     [][2]int `json:"udp_ports"`     // диапазоны портов для UDPUpstream
	UDPCIDRs     []string `json:"udp_cidrs"`     // и только к этим сетям (пусто - к любым, кроме игровых серверов)
	TelegramMode string   `json:"telegram_mode"` // auto | ws | direct
	DoH          bool     `json:"doh"`           // DNS (UDP 53) из туннеля - через зашифрованный DNS
	DoHProvider  string   `json:"doh_provider"`  // auto | cloudflare | google | ... | custom
	DoHCustom    string   `json:"doh_custom"`    // свой адрес https://.../dns-query
	DoHURL       string   `json:"doh_url"`       // адрес выбранного сервера (список серверов обновляется с GitHub)
	DoHIPs       []string `json:"doh_ips"`       // его IP (без обычного DNS)
}

// Stats - счётчики для отчётов
type Stats struct {
	TCP, UDP, QUICDropped, TGDirect, TGWS, Errors atomic.Int64
	DNS, DNSFail, AAAAEmpty, IPv6Refused          atomic.Int64
	ByGroup                                       sync.Map // upstream -> *atomic.Int64
}

type Router struct {
	cfg     Config
	Log     func(format string, a ...any)
	St      Stats
	tgpx    *tg.TGProxy
	ln      net.Listener
	tgBad   sync.Map // "/24 сети" -> time.Time до которого шлём через WebSocket
	tgFail  sync.Map // -> *failCount
	dns     *doh.Resolver
	udpNets []*net.IPNet

	v6mu    sync.Mutex
	v6ok    bool
	v6at    time.Time
	V6Check func() bool // проверка IPv6 у сети (для тестов подменяется)
}

// TunnelDNS - адрес DNS внутри туннеля (Android: DNS-сервер VPN при включённом DoH)
const TunnelDNS = "198.18.0.2"

// IPv6 - есть ли у настоящей сети выход в интернет по IPv6 (проверка раз в 15 с). Маршрутизатор
// работает в приложении, исключённом из своего VPN, поэтому видит таблицу маршрутов самой сети.
func (r *Router) IPv6() bool {
	r.v6mu.Lock()
	defer r.v6mu.Unlock()
	if time.Since(r.v6at) < 15*time.Second {
		return r.v6ok
	}
	chk := r.V6Check
	if chk == nil {
		chk = HasIPv6
	}
	r.v6ok, r.v6at = chk(), time.Now()
	return r.v6ok
}

// HasIPv6 - есть ли маршрут в интернет по IPv6 с глобальным адресом (UDP «connect» пакетов не шлёт)
func HasIPv6() bool {
	c, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.ParseIP("2001:4860:4860::8888"), Port: 53})
	if err != nil {
		return false
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

type failCount struct {
	mu    sync.Mutex
	n     int
	since time.Time
}

func New(cfg Config) *Router {
	if cfg.TelegramMode == "" {
		cfg.TelegramMode = "auto"
	}
	r := &Router{cfg: cfg, udpNets: mustCIDRs(cfg.UDPCIDRs...)}
	if cfg.DoH {
		// DoH напрямую; если провайдер его режет - через byedpi по умолчанию
		var fb doh.Dial
		if cfg.Default != "" {
			fb = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tg.SocksDial(cfg.Default, addr)
			}
		}
		if strings.HasPrefix(cfg.DoHURL, "https://") {
			r.dns = doh.NewProvider(&doh.Provider{ID: cfg.DoHProvider, URL: cfg.DoHURL, IPs: cfg.DoHIPs}, nil, fb)
		} else {
			r.dns = doh.NewFor(cfg.DoHProvider, cfg.DoHCustom, nil, fb)
		}
	}
	r.tgpx = &tg.TGProxy{Secret: make([]byte, 16), Log: func(f string, a ...any) { r.logf(f, a...) }}
	return r
}

// DNSStats - счётчики зашифрованного DNS (nil, если выключен)
func (r *Router) DNSStats() map[string]any {
	if r.dns == nil {
		return nil
	}
	cur := r.dns.Current()
	r.dns.Stats.Lock()
	defer r.dns.Stats.Unlock()
	return map[string]any{"queries": r.dns.Stats.Queries, "cache_hits": r.dns.Stats.CacheHits, "failures": r.dns.Stats.Failures,
		"last_error": r.dns.Stats.LastError, "current": cur}
}

func (r *Router) logf(format string, a ...any) {
	if r.Log != nil {
		r.Log(format, a...)
	}
}

func (r *Router) Listen() error {
	ln, err := net.Listen("tcp", r.cfg.Listen)
	if err != nil {
		return err
	}
	r.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.handle(c)
		}
	}()
	return nil
}

func (r *Router) Addr() string { return r.ln.Addr().String() }
func (r *Router) Close()       { r.ln.Close() }

// ---------- SOCKS5 сервер ----------

func readAddr(rd io.Reader, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(rd, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(rd, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(rd, l); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(rd, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", errors.New("SOCKS: неизвестный тип адреса")
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(rd, pb); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb)))), nil
}

func (r *Router) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil || h[0] != 5 {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, h[1])); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	target, err := readAddr(c, req[3])
	if err != nil {
		return
	}
	switch req[1] {
	case 1:
		r.handleConnect(c, target)
	case 3:
		r.handleUDP(c)
	default:
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

// ---------- TCP ----------

func (r *Router) handleConnect(c net.Conn, target string) {
	r.St.TCP.Add(1)
	host, port, _ := net.SplitHostPort(target)
	ip := net.ParseIP(host)
	// IPv6 там, где у сети его нет: сразу отказ. Иначе приложение считает соединение установленным
	// (ответ ниже даётся до подключения к серверу), шлёт запрос и получает обрыв - YouTube и другие
	// приложения не переходят на IPv4 и «не грузят», хотя проверки проходят
	if ip != nil && ip.To4() == nil && !r.IPv6() {
		r.St.IPv6Refused.Add(1)
		c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) // host unreachable
		return
	}
	// адрес DNS внутри туннеля: DNS по TCP - через зашифрованный DNS; DoT (853) там нет - сразу отказ,
	// чтобы «Частный DNS» не ждал тайм-аута
	if host == TunnelDNS {
		if port == "53" && r.dns != nil {
			c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			c.SetDeadline(time.Time{})
			r.serveTCPDNS(c)
			return
		}
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	// отвечаем сразу, чтобы прочитать начало соединения и понять, что это за сайт
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	first := make([]byte, 0, 4096)
	buf := make([]byte, 16<<10)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for len(first) < 64<<10 {
		c.SetReadDeadline(deadline)
		n, err := c.Read(buf)
		first = append(first, buf[:n]...)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break // сервер говорит первым или клиент молчит - решаем без имени
			}
			if len(first) == 0 {
				return
			}
			break
		}
		if ip != nil && tg.IsTelegramIP(ip) && len(first) >= 64 {
			break
		}
		if _, more := sniffHost(first); !more {
			break
		}
	}
	c.SetDeadline(time.Time{})

	// приложение Telegram к своим серверам
	if ip != nil && tg.IsTelegramIP(ip) && len(first) >= 64 {
		if r.telegram(c, target, ip, first) {
			return
		}
	}

	name, _ := sniffHost(first)
	if name == "" && ip == nil {
		name = strings.ToLower(host) // SOCKS с доменом
	}
	up := r.cfg.Default
	for _, g := range r.cfg.Groups {
		if name != "" && matchDomain(name, g.Domains) {
			up = g.Upstream
			break
		}
	}
	r.countGroup(up)
	r.pipeVia(c, up, target, first, nil)
}

func (r *Router) countGroup(up string) {
	v, _ := r.St.ByGroup.LoadOrStore(up, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
}

// pipeVia соединяет клиента с target через SOCKS5 upstream; done(получено байт) - по завершении
func (r *Router) pipeVia(c net.Conn, up, target string, first []byte, done func(got int64, d time.Duration)) {
	start := time.Now()
	var u net.Conn
	var err error
	if up == "direct" {
		// сервис без обхода (пользователь выбрал None): напрямую, как без программы
		u, err = net.DialTimeout("tcp", target, 10*time.Second)
	} else {
		u, err = tg.SocksDial(up, target)
	}
	if err != nil {
		r.St.Errors.Add(1)
		if done != nil {
			done(0, time.Since(start))
		}
		return
	}
	defer u.Close()
	if len(first) > 0 {
		if _, err := u.Write(first); err != nil {
			return
		}
	}
	var got atomic.Int64
	ch := make(chan struct{}, 2)
	go func() {
		io.Copy(u, c)
		if tc, ok := u.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		ch <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(c, u)
		got.Store(n)
		if tc, ok := c.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		ch <- struct{}{}
	}()
	<-ch
	// вторую сторону даём доделать, но не держим вечно
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
	}
	if done != nil {
		done(got.Load(), time.Since(start))
	}
}

// ---------- Telegram ----------

func tgKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d", v4[0], v4[1], v4[2])
	}
	return ip.String()
}

// telegram: true - соединение обслужено (через WebSocket или напрямую с учётом сбоев)
func (r *Router) telegram(c net.Conn, target string, ip net.IP, first []byte) bool {
	mode := r.cfg.TelegramMode
	if mode == "direct" {
		return false
	}
	key := tgKey(ip)
	useWS := mode == "ws"
	if v, ok := r.tgBad.Load(key); ok && time.Now().Before(v.(time.Time)) {
		useWS = true
	}
	if useWS {
		init := first[:64]
		rest := first[64:]
		cc := &prefixConn{Conn: c, prefix: rest}
		dial := func(addr string) (net.Conn, error) { return tg.SocksDial(r.cfg.Default, addr) }
		if r.tgpx.BridgeDirect(cc, init, ip, dial) {
			r.St.TGWS.Add(1)
			return true
		}
		// WebSocket не открылся - пробуем напрямую
	}
	r.St.TGDirect.Add(1)
	r.pipeVia(c, r.cfg.Default, target, first, func(got int64, d time.Duration) {
		if mode != "auto" {
			return
		}
		// сервер Telegram ничего не ответил - похоже на блокировку
		if got == 0 && d < 20*time.Second {
			v, _ := r.tgFail.LoadOrStore(key, &failCount{})
			fc := v.(*failCount)
			fc.mu.Lock()
			if time.Since(fc.since) > 2*time.Minute {
				fc.n, fc.since = 0, time.Now()
			}
			fc.n++
			n := fc.n
			fc.mu.Unlock()
			if n >= 2 {
				if _, was := r.tgBad.Load(key); !was {
					r.logf("Telegram: серверы %s.x не отвечают напрямую - перевожу на WebSocket", key)
				}
				r.tgBad.Store(key, time.Now().Add(15*time.Minute))
			}
		}
	})
	return true
}

// prefixConn - соединение, у которого начало уже прочитано
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// ---------- UDP ----------

// Игровые серверы: их UDP никогда не идёт в обход. Иначе подмена пакетов (она нужна голосу Discord)
// ломает игру: у Roblox - ошибки 277/279 и отключения (его игровой UDP тоже на портах 49152-65535).
var noBypassUDP = mustCIDRs(
	// Roblox (AS22697)
	"128.116.0.0/17", "209.206.40.0/21", "23.173.192.0/24", "103.140.28.0/23", "103.142.220.0/23",
	"141.193.3.0/24", "205.201.62.0/24", "204.9.184.0/24", "204.13.168.0/22",
)

// DiscordVoiceCIDRs - серверы голоса Discord (discord.media, AS49544)
var DiscordVoiceCIDRs = []string{"66.22.192.0/18", "138.128.136.0/21"}

func mustCIDRs(list ...string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range list {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func inNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *Router) udpViaUpstream(port int, host string) bool {
	if r.cfg.UDPUpstream == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || inNets(ip, noBypassUDP) {
		return false
	}
	if len(r.udpNets) > 0 && !inNets(ip, r.udpNets) {
		return false
	}
	for _, rg := range r.cfg.UDPPorts {
		if port >= rg[0] && port <= rg[1] {
			return true
		}
	}
	return false
}
