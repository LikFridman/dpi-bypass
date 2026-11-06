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
	"strings"
	"time"

	"dpibypass/tg"
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
	checkWS := flag.Bool("check-ws", false, "проверить маршрут WebSocket к web.telegram.org (через -socks, если задан) и выйти")
	discover := flag.Bool("discover", false, "найти и проверить публичные MTProto-прокси, вывести лучшие и выйти")
	want := flag.Int("want", 3, "сколько лучших прокси вывести (-discover)")
	var ups, srcs multi
	flag.Var(&ups, "up", "внешний прокси: tg://proxy?... или socks5://host:port (можно несколько)")
	flag.Var(&srcs, "src", "адрес списка прокси для -discover (можно несколько)")
	flag.Parse()
	setupResolver()

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
	if *discover {
		runDiscover(srcs, *socks, *want)
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
