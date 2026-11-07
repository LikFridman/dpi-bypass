package router

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSocks - поддельный byedpi: SOCKS5, запоминает адрес и первые байты, отвечает "ok"
func fakeSocks(t *testing.T, got chan<- string) net.Listener {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				g := make([]byte, 3)
				io.ReadFull(c, g)
				c.Write([]byte{5, 0})
				h := make([]byte, 4)
				io.ReadFull(c, h)
				target, _ := readAddr(c, h[3])
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				b := make([]byte, 4096)
				n, _ := c.Read(b)
				got <- target + "|" + strconv.Itoa(n)
				c.Write([]byte("ok"))
			}(c)
		}
	}()
	return ln
}

func socksConnect(t *testing.T, router, target string) net.Conn {
	c, err := net.Dial("tcp", router)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	host, port, _ := net.SplitHostPort(target)
	p, _ := strconv.Atoi(port)
	req := append([]byte{5, 1, 0, 1}, net.ParseIP(host).To4()...)
	req = append(req, byte(p>>8), byte(p))
	c.Write(req)
	io.ReadFull(c, make([]byte, 10))
	return c
}

func clientHello(sni string) []byte {
	a, b := net.Pipe()
	go tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake()
	buf := make([]byte, 4096)
	n, _ := b.Read(buf)
	a.Close()
	return buf[:n]
}

func TestSNIRouting(t *testing.T) {
	gotDef, gotYT := make(chan string, 4), make(chan string, 4)
	def, yt := fakeSocks(t, gotDef), fakeSocks(t, gotYT)
	defer def.Close()
	defer yt.Close()
	r := New(Config{Listen: "127.0.0.1:0", Default: def.Addr().String(),
		Groups: []Group{{Upstream: yt.Addr().String(), Domains: []string{"youtube.com", "googlevideo.com"}}}})
	if err := r.Listen(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if h, _ := sniffHost(clientHello("rr3---sn-abc.googlevideo.com")); h != "rr3---sn-abc.googlevideo.com" {
		t.Fatalf("SNI: %q", h)
	}

	c := socksConnect(t, r.Addr(), "142.250.1.1:443")
	c.Write(clientHello("www.youtube.com"))
	select {
	case g := <-gotYT:
		if g[:len("142.250.1.1:443")] != "142.250.1.1:443" {
			t.Fatalf("адрес %s", g)
		}
	case <-gotDef:
		t.Fatal("YouTube ушёл не в свою группу")
	case <-time.After(3 * time.Second):
		t.Fatal("таймаут")
	}
	c.Close()

	c = socksConnect(t, r.Addr(), "1.1.1.1:443")
	c.Write(clientHello("example.org"))
	select {
	case <-gotDef:
	case <-gotYT:
		t.Fatal("чужой сайт ушёл в группу YouTube")
	case <-time.After(3 * time.Second):
		t.Fatal("таймаут")
	}
	resp := make([]byte, 2)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, resp); err != nil || string(resp) != "ok" {
		t.Fatalf("ответ %q %v", resp, err)
	}
	c.Close()

	// HTTP: Host
	c = socksConnect(t, r.Addr(), "142.250.1.2:80")
	c.Write([]byte("GET / HTTP/1.1\r\nHost: m.youtube.com\r\n\r\n"))
	select {
	case <-gotYT:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP Host не распознан")
	}
	c.Close()
}

func TestUDP(t *testing.T) {
	echo, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer echo.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.WriteToUDP(b[:n], a)
		}
	}()
	r := New(Config{Listen: "127.0.0.1:0", Default: "127.0.0.1:1", BlockQUIC: true})
	r.Listen()
	defer r.Close()

	c, _ := net.Dial("tcp", r.Addr())
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 10)
	io.ReadFull(c, rep)
	relay := &net.UDPAddr{IP: net.IP(rep[4:8]), Port: int(binary.BigEndian.Uint16(rep[8:10]))}
	u, _ := net.DialUDP("udp", nil, relay)
	defer u.Close()

	// QUIC - отбрасывается
	q := append([]byte{0, 0, 0, 1, 8, 8, 8, 8, 1, 187}, []byte("quic")...)
	u.Write(q)
	// обычный UDP - напрямую, эхо возвращается с заголовком
	ep := echo.LocalAddr().(*net.UDPAddr).Port
	pkt := append([]byte{0, 0, 0, 1, 127, 0, 0, 1, byte(ep >> 8), byte(ep)}, []byte("hello")...)
	u.Write(pkt)
	u.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 2048)
	n, err := u.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b[:n], pkt) {
		t.Fatalf("эхо %x", b[:n])
	}
	time.Sleep(100 * time.Millisecond)
	if r.St.QUICDropped.Load() != 1 {
		t.Fatalf("QUIC не отброшен: %d", r.St.QUICDropped.Load())
	}
}

func TestUDPGameTrafficStaysDirect(t *testing.T) {
	r := New(Config{UDPUpstream: "127.0.0.1:1", UDPPorts: [][2]int{{50000, 65535}}, UDPCIDRs: DiscordVoiceCIDRs})
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"66.22.200.10", 50010, true},   // голос Discord
		{"128.116.10.20", 55000, false}, // игровой сервер Roblox
		{"8.8.8.8", 55000, false},       // не Discord
		{"66.22.200.10", 3478, false},   // другой порт
	}
	for _, c := range cases {
		if got := r.udpViaUpstream(c.port, c.host); got != c.want {
			t.Errorf("%s:%d -> %v, ожидалось %v", c.host, c.port, got, c.want)
		}
	}
	r2 := New(Config{UDPUpstream: "127.0.0.1:1", UDPPorts: [][2]int{{50000, 65535}}})
	if r2.udpViaUpstream(55000, "128.116.1.1") {
		t.Error("Roblox не должен идти в обход даже без списка сетей")
	}
}

// Сеть без IPv6: соединение к IPv6-адресу отклоняется сразу (а не «принято и оборвано»),
// AAAA-запросы получают пустой ответ, к адресу DNS туннеля на 853 - отказ
func TestNoIPv6(t *testing.T) {
	got := make(chan string, 4)
	up := fakeSocks(t, got)
	defer up.Close()
	r := New(Config{Listen: "127.0.0.1:0", Default: up.Addr().String()})
	r.V6Check = func() bool { return false }
	if err := r.Listen(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	reply := func(req []byte) byte {
		c, err := net.Dial("tcp", r.Addr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte{5, 1, 0})
		io.ReadFull(c, make([]byte, 2))
		c.Write(req)
		h := make([]byte, 10)
		if _, err := io.ReadFull(c, h); err != nil {
			t.Fatalf("нет ответа SOCKS: %v", err)
		}
		return h[1]
	}
	v6 := append([]byte{5, 1, 0, 4}, net.ParseIP("2a00:1450:4010:c05::5b").To16()...)
	if code := reply(append(v6, 1, 187)); code != 4 {
		t.Fatalf("IPv6 без IPv6 у сети: код %d, нужен 4", code)
	}
	dot := append([]byte{5, 1, 0, 1}, net.ParseIP(TunnelDNS).To4()...)
	if code := reply(append(dot, 3, 85)); code != 5 {
		t.Fatalf("DoT к DNS туннеля: код %d, нужен 5", code)
	}
	if r.St.IPv6Refused.Load() != 1 {
		t.Fatal("счётчик IPv6")
	}
	select {
	case s := <-got:
		t.Fatalf("соединение не должно было уйти в byedpi: %s", s)
	default:
	}

	// AAAA: пустой ответ NOERROR с тем же вопросом
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'y', 'o', 'u', 't', 'u', 'b', 'e', 3, 'c', 'o', 'm', 0, 0, 28, 0, 1}
	if dnsQType(q) != 28 {
		t.Fatalf("тип запроса %d", dnsQType(q))
	}
	e := dnsEmpty(q)
	if len(e) != len(q) || e[0] != 0x12 || e[2]&0x80 == 0 || e[3]&0x0f != 0 || binary.BigEndian.Uint16(e[6:]) != 0 {
		t.Fatalf("плохой пустой ответ % x", e)
	}
	q[len(q)-3] = 1
	if dnsQType(q) != 1 {
		t.Fatal("A-запрос")
	}
}

// Сеть с IPv6: соединение к IPv6 идёт как обычно
func TestWithIPv6(t *testing.T) {
	got := make(chan string, 4)
	up := fakeSocks(t, got)
	defer up.Close()
	r := New(Config{Listen: "127.0.0.1:0", Default: up.Addr().String()})
	r.V6Check = func() bool { return true }
	r.Listen()
	defer r.Close()
	c, _ := net.Dial("tcp", r.Addr())
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	c.Write(append(append([]byte{5, 1, 0, 4}, net.ParseIP("2a00:1450:4010:c05::5b").To16()...), 1, 187))
	h := make([]byte, 10)
	io.ReadFull(c, h)
	if h[1] != 0 {
		t.Fatalf("код %d", h[1])
	}
	c.Write(clientHello("www.youtube.com"))
	select {
	case s := <-got:
		if !strings.HasPrefix(s, "[2a00:1450:4010:c05::5b]:443|") {
			t.Fatal(s)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("не дошло до byedpi")
	}
}

// Маршрут сервиса: основной способ не соединяется - сразу запасной; после трёх «сервер молчит»
// основной помечается сломанным и выбирается запасной
func TestRouteFailover(t *testing.T) {
	got := make(chan string, 8)
	backup := fakeSocks(t, got)
	defer backup.Close()
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close() // порт закрыт - соединиться нельзя

	r := New(Config{Listen: "127.0.0.1:0", Default: backup.Addr().String(), Groups: []Group{
		{Name: "YouTube", Upstreams: []string{deadAddr, backup.Addr().String()}, Domains: []string{"youtube.com"}},
	}})
	r.V6Check = func() bool { return false }
	if err := r.Listen(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i := 0; i < 4; i++ {
		c := socksConnect(t, r.Addr(), "142.250.1.1:443")
		c.Write(clientHello("www.youtube.com"))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		b := make([]byte, 2)
		if _, err := io.ReadFull(c, b); err != nil || string(b) != "ok" {
			t.Fatalf("соединение %d не прошло через запасной: %v", i, err)
		}
		c.Close()
		<-got
	}
	ri := r.Routes()
	if len(ri) != 1 || ri[0].Active != backup.Addr().String() {
		t.Fatalf("активный способ: %+v", ri)
	}
	if !ri[0].Ups[0].Bad {
		t.Fatal("основной способ должен быть помечен сломанным")
	}
}

// Telegram: соединение приложения (MTProto к адресу Telegram) идёт по способу VPN (SOCKS) как есть,
// а способы tg-ws/tg-proxy для обычных сайтов telegram.org пропускаются
func TestRouteTelegramKinds(t *testing.T) {
	got := make(chan string, 8)
	vpnUp := fakeSocks(t, got)
	defer vpnUp.Close()
	other := make(chan string, 8)
	def := fakeSocks(t, other)
	defer def.Close()
	r := New(Config{Listen: "127.0.0.1:0", Default: def.Addr().String(), Groups: []Group{
		{Name: "Telegram", Upstreams: []string{UpTGProxy, vpnUp.Addr().String()}, Domains: []string{"telegram.org"},
			CIDRs: []string{"149.154.160.0/20"}, Check: "tg"},
	}})
	r.V6Check = func() bool { return false }
	r.Listen()
	defer r.Close()
	// MTProto: прокси нет (tg-proxy не сработает) - VPN
	c := socksConnect(t, r.Addr(), "149.154.167.51:443")
	init := make([]byte, 64)
	for i := range init {
		init[i] = byte(i*7 + 3)
	}
	c.Write(init)
	select {
	case s := <-got:
		if !strings.HasPrefix(s, "149.154.167.51:443|") {
			t.Fatal(s)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("MTProto не ушёл в VPN")
	}
	c.Close()
	// сайт telegram.org: tg-proxy пропущен, сразу VPN
	c = socksConnect(t, r.Addr(), "149.154.167.99:443")
	c.Write(clientHello("web.telegram.org"))
	select {
	case s := <-got:
		if !strings.HasPrefix(s, "149.154.167.99:443|") {
			t.Fatal(s)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("сайт Telegram не ушёл в VPN")
	}
	c.Close()
	select {
	case s := <-other:
		t.Fatalf("ничего не должно идти мимо маршрута: %s", s)
	default:
	}
}

// «Самый быстрый»: основной способ выбирается по задержке проверки
func TestRouteFastest(t *testing.T) {
	r := New(Config{Listen: "127.0.0.1:0", Groups: []Group{
		{Name: "Telegram", Upstreams: []string{"a", "b", "c"}, Fastest: true},
	}})
	rt := r.routes[0]
	rt.state("a").checked, rt.state("a").ok, rt.state("a").ping = true, true, 300
	rt.state("b").checked, rt.state("b").ok, rt.state("b").ping = true, true, 90
	rt.state("c").checked, rt.state("c").ok = true, false
	if p := rt.pick(true); p[0] != "b" || p[1] != "a" || p[2] != "c" {
		t.Fatal(p)
	}
	rt.state("b").badUntil = time.Now().Add(time.Minute)
	if p := rt.pick(true); p[0] != "a" || p[len(p)-1] != "b" {
		t.Fatal(p)
	}
}

// Список MTProto-прокси меняется на ходу (без перезапуска маршрутизатора)
func TestSetTGProxies(t *testing.T) {
	r := New(Config{Listen: "127.0.0.1:0"})
	n := r.SetTGProxies([]string{"tg://proxy?server=1.2.3.4&port=443&secret=00112233445566778899aabbccddeeff", "мусор"})
	if n != 1 {
		t.Fatal(n)
	}
	if r.SetTGProxies(nil) != 0 {
		t.Fatal("не очистился")
	}
}

// resetSocks - SOCKS, который принимает соединение, читает ClientHello и сразу закрывает (как DPI/плохой сервер)
func resetSocks(t *testing.T) net.Listener {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				g := make([]byte, 3)
				io.ReadFull(c, g)
				c.Write([]byte{5, 0})
				h := make([]byte, 4)
				io.ReadFull(c, h)
				readAddr(c, h[3])
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				c.Read(make([]byte, 4096))
				c.Close()
			}(c)
		}
	}()
	return ln
}

// Сервер сбросил соединение, ничего не прислав: приложение этого не видит - то же начало уходит запасным способом
func TestRouteRetryOnEarlyReset(t *testing.T) {
	got := make(chan string, 8)
	backup := fakeSocks(t, got)
	defer backup.Close()
	bad := resetSocks(t)
	defer bad.Close()
	r := New(Config{Listen: "127.0.0.1:0", Default: backup.Addr().String(), Groups: []Group{
		{Name: "X", Upstreams: []string{bad.Addr().String(), backup.Addr().String()}, Domains: []string{"x.com"}},
	}})
	r.V6Check = func() bool { return false }
	if err := r.Listen(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	hello := clientHello("x.com")
	c := socksConnect(t, r.Addr(), "104.244.42.1:443")
	c.Write(hello)
	c.SetReadDeadline(time.Now().Add(4 * time.Second))
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ok" {
		t.Fatalf("не перешло на запасной без обрыва: %v %q", err, b)
	}
	c.Close()
	if g := <-got; !strings.HasSuffix(g, "|"+strconv.Itoa(len(hello))) {
		t.Fatalf("запасной получил не то начало: %s", g)
	}
}

// Проверка способов: текущий не отвечает, запасной отвечает - переключение сразу
func TestCheckSwitchesToWorkingBackup(t *testing.T) {
	r := New(Config{Listen: "127.0.0.1:0", Groups: []Group{{Name: "X", Upstreams: []string{"a", "b"}, Domains: []string{"x.com"}}}})
	rt := r.routes[0]
	rt.state("a").checked, rt.state("a").ok, rt.state("a").checkedAt = true, false, time.Now()
	rt.state("b").checked, rt.state("b").ok, rt.state("b").checkedAt = true, true, time.Now()
	// checkRoute без сети: эмулируем его хвост - вызов с уже проверенными состояниями
	r.routes[0].g.Upstreams = []string{"a", "b"}
	cur := rt.pick(false)
	if cur[0] != "a" {
		t.Fatal(cur)
	}
	r.afterCheck(rt)
	if p := rt.pick(false); p[0] != "b" {
		t.Fatalf("не переключился: %v", p)
	}
}
