// tgproxy - локальный MTProto-прокси для Telegram на Android (запускается приложением
// dpi-bypass как libtgproxy.so). Telegram подключается к 127.0.0.1, а трафик идёт
// WebSocket'ом к web.telegram.org через byedpi, напрямую, через свой Cloudflare Worker
// или через внешний прокси.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"dpibypass/tg"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	listen := flag.String("listen", "127.0.0.1:1443", "адрес прокси")
	secretHex := flag.String("secret", "", "секрет (32 hex)")
	socks := flag.String("socks", "", "SOCKS5 обхода DPI (byedpi), например 127.0.0.1:1080")
	worker := flag.String("worker", "", "свой Cloudflare Worker")
	check := flag.String("check", "", "проверить уже запущенный прокси по этому адресу и выйти")
	var ups multi
	flag.Var(&ups, "up", "внешний прокси: tg://proxy?... или socks5://host:port (можно несколько)")
	flag.Parse()

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

	// на Android нет /etc/resolv.conf - спрашиваем DNS напрямую
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
	}
}
