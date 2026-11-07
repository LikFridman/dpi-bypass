// tgproxy - локальный MTProto-прокси для Telegram на Android (запускается приложением
// dpi-bypass как libtgproxy.so). Telegram подключается к 127.0.0.1, а трафик идёт
// WebSocket'ом к web.telegram.org через byedpi, напрямую, через свой Cloudflare Worker
// или через внешний прокси.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	svc "dpibypass/check"
	"dpibypass/doh"
	"dpibypass/router"
	"dpibypass/speed"
	"dpibypass/tg"
	"dpibypass/vpn"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	// Go для linux не знает, где на Android лежат корневые сертификаты - без этого
	// не проверяется TLS ни у web.telegram.org (WebSocket), ни у списков прокси
	if os.Getenv("SSL_CERT_DIR") == "" {
		var dirs []string
		for _, d := range []string{"/apex/com.android.conscrypt/cacerts", "/system/etc/security/cacerts"} {
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				dirs = append(dirs, d)
			}
		}
		if len(dirs) > 0 {
			os.Setenv("SSL_CERT_DIR", strings.Join(dirs, ":"))
		}
	}
	listen := flag.String("listen", "127.0.0.1:1443", "адрес прокси")
	secretHex := flag.String("secret", "", "секрет (32 hex)")
	socks := flag.String("socks", "", "SOCKS5 обхода DPI (byedpi), например 127.0.0.1:1080")
	worker := flag.String("worker", "", "свой Cloudflare Worker")
	check := flag.String("check", "", "проверить уже запущенный прокси по этому адресу и выйти")
	checkSites := flag.String("check-sites", "", "проверить сервисы из JSON-файла (через -socks, если задан) и выйти")
	light := flag.Bool("light", false, "облегчённая проверка (для перебора стратегий)")
	quick := flag.Bool("quick", false, "фоновая проверка: только начало страницы")
	useDoH := flag.Bool("doh", false, "проверки: имена сайтов - через зашифрованный DNS (как при включённом обходе)")
	dnsID := flag.String("dns", "auto", "сервер зашифрованного DNS (cloudflare, google, adguard, ... или custom)")
	dnsCustom := flag.String("dns-custom", "", "свой адрес DoH для -dns custom")
	dnsPing := flag.Bool("dns-ping", false, "проверить задержку до всех серверов DoH, вывести DNSPING <json> и выйти")
	dnsURL := flag.String("dns-url", "", "адрес выбранного сервера DoH (вместо -dns)")
	dnsIPs := flag.String("dns-ips", "", "его IP через запятую")
	dnsList := flag.String("dns-list", "", "файл JSON со списком серверов для -dns-ping")
	routerCfg := flag.String("router", "", "запустить маршрутизатор SOCKS5 по JSON-настройкам из файла")
	speedTest := flag.Bool("speed", false, "замерить скорость видео YouTube (через -socks, если задан) и выйти")
	checkDC := flag.Bool("check-dc", false, "проверить Telegram как приложение: MTProto напрямую к DC2 (через -socks, если задан) и выйти")
	checkWS := flag.Bool("check-ws", false, "проверить маршрут WebSocket к web.telegram.org (через -socks, если задан) и выйти")
	discover := flag.Bool("discover", false, "найти и проверить публичные MTProto-прокси, вывести лучшие и выйти")
	want := flag.Int("want", 3, "сколько лучших прокси вывести (-discover)")
	vpnTest := flag.String("vpn-test", "", "проверить серверы VPN из JSON-файла {xray, links, telegram, speed}, вывести VPNTEST <json> и выйти")
	warp := flag.Bool("warp", false, "зарегистрировать бесплатный Cloudflare WARP (через -socks, если задан), вывести WARP <json> и выйти")
	var ups, srcs multi
	flag.Var(&ups, "up", "внешний прокси: tg://proxy?... или socks5://host:port (можно несколько)")
	flag.Var(&srcs, "src", "адрес списка прокси для -discover (можно несколько)")
	flag.Parse()
	setupResolver()

	if *checkDC {
		dial := func(addr string) (net.Conn, error) { return net.DialTimeout("tcp", addr, 6*time.Second) }
		if *socks != "" {
			dial = func(addr string) (net.Conn, error) { return tg.SocksDial(*socks, addr) }
		}
		d, err := tg.CheckDC(dial, 2, 10*time.Second)
		if err != nil {
			fmt.Printf("CHECK FAIL %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("CHECK OK %d\n", d.Milliseconds())
		return
	}
	if *checkWS {
		px := &tg.TGProxy{Secret: make([]byte, 16)}
		r := px.BaseRoutes()[0]
		if *socks != "" {
			r = px.WSSocksRoute("WebSocket через обход", *socks)
		}
		px.Routes = func() []tg.TGRoute { return []tg.TGRoute{r} }
		if err := px.Listen("127.0.0.1:0"); err != nil {
			fmt.Printf("CHECK FAIL %v\n", err)
			os.Exit(1)
		}
		d, err := tg.CheckTimeout(px.Addr(), px.Secret, 2, 15*time.Second)
		if err != nil {
			fmt.Printf("CHECK FAIL %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("CHECK OK %d\n", d.Milliseconds())
		return
	}
	if *vpnTest != "" {
		runVPNTest(*vpnTest)
		return
	}
	if *warp {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		var dial func(ctx context.Context, network, addr string) (net.Conn, error)
		if *socks != "" {
			s := *socks
			dial = func(ctx context.Context, network, addr string) (net.Conn, error) { return tg.SocksDial(s, addr) }
		}
		a, err := vpn.RegisterWarp(ctx, dial)
		cancel()
		if err != nil {
			fmt.Printf("ERR %v\n", err)
			os.Exit(1)
		}
		b, _ := json.Marshal(map[string]any{"account": a, "links": a.Links()})
		fmt.Printf("WARP %s\n", b)
		return
	}
	if *discover {
		runDiscover(srcs, *socks, *want)
		return
	}
	if *dnsPing {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		prov := doh.Providers
		if *dnsList != "" {
			if b, err := os.ReadFile(*dnsList); err == nil {
				var l []doh.Provider
				if json.Unmarshal(b, &l) == nil && len(l) > 0 {
					prov = l
				}
			}
		}
		res := doh.PingList(ctx, prov, *dnsCustom, nil)
		cancel()
		b, _ := json.Marshal(res)
		fmt.Println("DNSPING " + string(b))
		return
	}
	if *checkSites != "" {
		b, err := os.ReadFile(*checkSites)
		if err != nil {
			fmt.Printf("ERR %v\n", err)
			os.Exit(2)
		}
		var sites []svc.Site
		if err := json.Unmarshal(b, &sites); err != nil {
			fmt.Printf("ERR %v\n", err)
			os.Exit(2)
		}
		dial := svc.Direct(6 * time.Second)
		if *socks != "" {
			dial = svc.Socks(*socks)
		}
		var mu sync.Mutex
		if *useDoH {
			res := doh.NewFor(*dnsID, *dnsCustom, nil, nil)
			if strings.HasPrefix(*dnsURL, "https://") {
				var ips []string
				for _, x := range strings.Split(*dnsIPs, ",") {
					if x = strings.TrimSpace(x); x != "" {
						ips = append(ips, x)
					}
				}
				res = doh.NewProvider(&doh.Provider{ID: *dnsID, URL: *dnsURL, IPs: ips}, nil, nil)
			}
			dial = svc.Dial(res.Wrap(doh.Dial(dial)))
		}
		svc.RunAll(context.Background(), sites, dial, svc.Options{Light: *light, Quick: *quick}, func(r svc.Result) {
			j, _ := json.Marshal(r)
			mu.Lock()
			fmt.Printf("SITE %s\n", j)
			mu.Unlock()
		})
		fmt.Println("DONE")
		return
	}
	if *routerCfg != "" {
		runRouter(*routerCfg)
		return
	}
	if *speedTest {
		cl := &http.Client{Timeout: 20 * time.Second}
		if *socks != "" {
			sa := *socks
			cl.Transport = &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tg.SocksDial(sa, addr)
			}}
		}
		r, err := speed.YouTube(cl, 6*time.Second)
		if err != nil {
			fmt.Printf("SPEED FAIL %v\n", err)
			os.Exit(1)
		}
		b, _ := json.Marshal(r)
		fmt.Printf("SPEED %s\n", b)
		return
	}

	secret, err := hex.DecodeString(*secretHex)
	if err != nil || len(secret) != 16 {
		fmt.Println("ERR нужен -secret из 32 hex-символов")
		os.Exit(2)
	}

	if *check != "" {
		d, err := tg.Check(*check, secret, 2)
		if err != nil {
			fmt.Printf("CHECK FAIL %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("CHECK OK %d\n", d.Milliseconds())
		return
	}

	px := &tg.TGProxy{
		Secret: secret,
		Resolve: func(host string) net.IP {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
			if err != nil || len(ips) == 0 {
				return nil
			}
			return ips[0]
		},
		Log: func(format string, a ...any) { fmt.Println("LOG " + fmt.Sprintf(format, a...)) },
	}
	var upRoutes []tg.TGRoute
	for _, l := range ups {
		u, err := tg.ParseUpstream(l)
		if err != nil {
			fmt.Printf("LOG Telegram: ссылка на прокси не подходит (%v)\n", err)
			continue
		}
		upRoutes = append(upRoutes, u.Route())
		fmt.Printf("LOG Telegram: запасной прокси %s\n", u)
	}
	base := px.BaseRoutes() // WebSocket напрямую, TCP напрямую
	var routes []tg.TGRoute
	if *socks != "" {
		routes = append(routes, px.WSSocksRoute("WebSocket через обход", *socks))
	}
	routes = append(routes, base[0])
	if *worker != "" {
		routes = append(routes, px.WorkerRoute(*worker))
	}
	routes = append(routes, upRoutes...)
	routes = append(routes, base[1])
	px.Routes = func() []tg.TGRoute { return routes }

	if err := px.Listen(*listen); err != nil {
		fmt.Printf("ERR %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("READY %s\n", px.Addr())
	for {
		time.Sleep(3 * time.Second)
		a, t, ws, tcp, f := px.Stats()
		fmt.Printf("STATS %d %d %d %d %d\n", a, t, ws, tcp, f)
		if rs := px.RouteStats(); len(rs) > 0 {
			if b, err := json.Marshal(rs); err == nil {
				fmt.Printf("ROUTES %s\n", b)
			}
		}
	}
}

// на Android нет /etc/resolv.conf - спрашиваем DNS напрямую
func setupResolver() {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	servers := []string{"1.1.1.1:53", "8.8.8.8:53", "77.88.8.8:53"}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var last error
		for _, s := range servers {
			c, err := dialer.DialContext(ctx, network, s)
			if err == nil {
				return c, nil
			}
			last = err
		}
		return nil, last
	}}
}

// runDiscover: списки скачиваются напрямую, а если не вышло - через обход (byedpi)
func runDiscover(srcs []string, socks string, want int) {
	if len(srcs) == 0 {
		srcs = tg.DefaultSources
	}
	logf := func(format string, a ...any) { fmt.Println("LOG " + fmt.Sprintf(format, a...)) }
	cl := &http.Client{Timeout: 12 * time.Second}
	cands := tg.FetchCandidates(srcs, cl, logf)
	if len(cands) == 0 && socks != "" {
		cl.Transport = &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tg.SocksDial(socks, addr)
		}}
		cands = tg.FetchCandidates(srcs, cl, logf)
	}
	if len(cands) > 300 {
		cands = cands[:300]
	}
	fmt.Printf("LOG Telegram: проверяю %d публичных прокси\n", len(cands))
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for _, f := range tg.Discover(ctx, cands, want, logf) {
		b, _ := json.Marshal(f)
		fmt.Printf("FOUND %s\n", b)
	}
	fmt.Println("DONE")
}

// runRouter - маршрутизатор между VPN-туннелем и byedpi (см. пакет router)
func runRouter(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("ERR %v\n", err)
		os.Exit(2)
	}
	var cfg router.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		fmt.Printf("ERR %v\n", err)
		os.Exit(2)
	}
	r := router.New(cfg)
	r.Log = func(format string, a ...any) { fmt.Println("LOG " + fmt.Sprintf(format, a...)) }
	r.XraySetup = childSetup
	if err := r.Listen(); err != nil {
		fmt.Printf("ERR %v\n", err)
		os.Exit(1)
	}
	// остановка приложением: сначала Xray, потом выход
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; r.Close(); os.Exit(0) }()
	fmt.Printf("READY %s\n", r.Addr())
	for {
		time.Sleep(10 * time.Second)
		groups := map[string]int64{}
		r.St.ByGroup.Range(func(k, v any) bool {
			groups[k.(string)] = v.(*atomic.Int64).Load()
			return true
		})
		st, _ := json.Marshal(map[string]any{"tcp": r.St.TCP.Load(), "udp": r.St.UDP.Load(), "quic_dropped": r.St.QUICDropped.Load(),
			"tg_direct": r.St.TGDirect.Load(), "tg_ws": r.St.TGWS.Load(), "errors": r.St.Errors.Load(), "groups": groups,
			"dns": r.St.DNS.Load(), "dns_fail": r.St.DNSFail.Load(), "doh": r.DNSStats(),
			"ipv6": r.IPv6(), "aaaa_empty": r.St.AAAAEmpty.Load(), "ipv6_refused": r.St.IPv6Refused.Load(),
			"routes": r.Routes(), "vpn": r.VPNAlive()})
		fmt.Printf("RSTATS %s\n", st)
	}
}

// runVPNTest - проверка серверов VPN (для приложения): VPNTEST [{id, ok, ping, tg, kbps, err}...]
func runVPNTest(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("ERR %v\n", err)
		os.Exit(2)
	}
	var req struct {
		Xray     string   `json:"xray"`
		Links    []string `json:"links"`
		Sources  []string `json:"sources"` // откуда ссылка (own, sub, free, warp) - по порядку
		Telegram bool     `json:"telegram"`
		Speed    int      `json:"speed"`
		Timeout  int      `json:"timeout"` // с
	}
	if err := json.Unmarshal(b, &req); err != nil {
		fmt.Printf("ERR %v\n", err)
		os.Exit(2)
	}
	var list []*vpn.Server
	var bad []vpn.Result
	for i, l := range req.Links {
		s, err := vpn.Parse(l)
		if err != nil {
			bad = append(bad, vpn.Result{Err: "ссылка: " + err.Error(), Link: l})
			continue
		}
		if i < len(req.Sources) {
			s.Source = req.Sources[i]
		}
		list = append(list, s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	o := vpn.TestOpts{Telegram: req.Telegram, Speed: req.Speed, Setup: childSetup}
	if req.Timeout > 0 {
		o.Timeout = time.Duration(req.Timeout) * time.Second
	}
	res := vpn.Test(ctx, req.Xray, list, o)
	for i := range res {
		res[i].Link = list[i].Link
	}
	out, _ := json.Marshal(append(res, bad...))
	fmt.Printf("VPNTEST %s\n", out)
}
