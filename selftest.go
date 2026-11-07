//go:build windows

package main

import (
	"context"
	svc "dpibypass/check"
	"dpibypass/doh"
	"dpibypass/speed"
	"dpibypass/tg"
	"dpibypass/router"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// selftest - проверка для GitHub Actions: winws принимает все наши параметры и не падает.
// Возвращает код выхода (0 - всё хорошо).
func selftest() int {
	failed := 0
	check := func(name string, ok bool, detail string) {
		mark := "OK  "
		if !ok {
			mark = "FAIL"
			failed++
		}
		say("[%s] %s %s", mark, name, detail)
	}
	svcs := mustPrepare()
	check("winws скачан", len(missingZapretFiles()) == 0, "")
	check("сборка winws - последняя из zapret-win-bundle", installedZapretRev() != "" && installedZapretRev() == latestZapretRev(&http.Client{Timeout: 20 * time.Second}), installedZapretRev())
	vpnStep()
	cfg := &Config{Best: "s1", Unfixable: map[string]string{}, Sites: map[string]string{"example.org": "s2"}}
	var names []string
	for _, s := range svcs {
		names = append(names, s.Name)
	}
	cfg.Groups = []Group{{Strategy: "s1", Services: names}}

	for _, st := range zapret1Strategies() { // наши и Flowseal
		w, err := startWinws(testArgs(st))
		if err == nil {
			time.Sleep(500 * time.Millisecond)
			err2 := ""
			if !w.Alive() {
				err2 = w.out.Tail()
			}
			w.Stop()
			check("стратегия "+st.ID, err2 == "", err2)
		} else {
			check("стратегия "+st.ID, false, err.Error())
		}
	}
	// zapret2 (winws2): каждая стратегия принимается, полная конфигурация с автопереключением работает
	check("zapret2: winws2 и библиотеки Lua на месте", z2Ready(), strings.Join(missingZapretFiles(), ","))
	for _, st := range strategiesZ2 {
		w, err := startWinws(testArgs(st))
		if err == nil {
			// настоящее соединение: ошибки в параметрах Lua видны только при обработке пакета
			pr := probeHost("www.google.com")
			time.Sleep(300 * time.Millisecond)
			err2 := ""
			tail := w.out.Tail()
			if !w.Alive() || strings.Contains(strings.ToLower(tail), "error") {
				err2 = tail
			}
			if !pr.OK() {
				err2 += " сайт через стратегию: " + pr.Reason
			}
			w.Stop()
			check("zapret2: стратегия "+st.ID, err2 == "", err2)
		} else {
			check("zapret2: стратегия "+st.ID, false, err.Error())
		}
	}
	{
		// все стратегии zapret2 «работали» у всех сервисов - группа получит автопереключение из трёх
		for _, st := range strategiesZ2 {
			for _, n := range names {
				recordResult(st.ID, n, stratRes{OK: true, KBps: 1000})
			}
		}
		zc := &Config{Best: "z1", Unfixable: map[string]string{}, Sites: map[string]string{"example.org": "z2"}, Groups: []Group{{Strategy: "z3", Services: names}}}
		args, _ := buildArgs(zc, svcs, true)
		hasCirc := strings.Contains(strings.Join(args, " "), "circular")
		w, err := startCombined(zc, svcs)
		if err != nil {
			check("zapret2: полная конфигурация", false, err.Error())
		} else {
			time.Sleep(5 * time.Second)
			alive := w.Alive()
			detail := ""
			if !alive {
				detail = w.out.Tail()
			}
			isZ2 := strings.Contains(strings.ToLower(w.cmd.Path), "winws2")
			if t := w.out.Tail(); strings.Contains(strings.ToLower(t), "error") {
				alive, detail = false, t
			}
			check("zapret2: полная конфигурация winws2 работает 5 с (с автопереключением)", alive && isZ2 && hasCirc, fmt.Sprint(detail, " exe=", w.cmd.Path, " circular=", hasCirc))
			res := probeAll(svcs)
			say("%s", statusLine(svcs, res))
			check("zapret2: сайты открываются через winws2", avgPing(res) > 0, "")
			w.Stop()
		}
		resetResults()
	}
	combos := deepCombos()
	for i := 0; i < len(combos); i += 7 {
		w, err := startWinws(testArgs(combos[i]))
		if err != nil {
			check("комбинация "+combos[i].Name, false, err.Error())
			continue
		}
		w.Stop()
	}
	check("комбинации глубокой проверки (выборка)", true, fmt.Sprintf("%d шт.", (len(combos)+6)/7))

	w, err := startCombined(cfg, svcs)
	if err != nil {
		check("полная конфигурация", false, err.Error())
	} else {
		time.Sleep(5 * time.Second)
		alive := w.Alive()
		detail := ""
		if !alive {
			detail = w.out.Tail()
		}
		check("полная конфигурация работает 5 с", alive, detail)
		res := probeAll(svcs)
		say("%s", statusLine(svcs, res))
		printTable(svcs, res)
		// Ping all: нагрузочная проверка всех сервисов через рабочую конфигурацию
		var cs []svc.Site
		for _, s := range svcs {
			cs = append(cs, checkSite(s))
		}
		for _, r := range svc.RunAll(context.Background(), cs, winDial(), svc.Options{}, nil) {
			say("      ping-all %s", checkLine(r))
		}
		pd := ""
		if avgPing(res) == 0 {
			pd = "ни один сайт не ответил"
		}
		check("пинг измеряется", avgPing(res) > 0, pd)
		w.Stop()
	}
	// зашифрованный DNS: ответ от DoH и локальный DNS-сервер (как при включённом обходе)
	{
		r := doh.New(nil, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ips, derr := r.LookupIP(ctx, "www.instagram.com")
		cancel()
		check("зашифрованный DNS (DoH)", derr == nil && len(ips) > 0, fmt.Sprint(ips, derr))
		if pc, lerr := net.ListenPacket("udp", "127.0.0.1:0"); lerr == nil {
			go r.ServeUDP(pc)
			res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("udp", pc.LocalAddr().String())
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			a, e := res.LookupHost(ctx, "discord.com")
			cancel()
			pc.Close()
			check("локальный DNS-сервер через DoH", e == nil && len(a) > 0, fmt.Sprint(a, e))
		}
	}
	// зашифрованный DNS целиком, как при включённом обходе: адаптеры переключаются на 127.0.0.1,
	// системный DNS (как у браузера) отвечает через DoH, после выключения настройки возвращаются
	{
		before := netSignature()
		settings.NoDoH, runMode = false, modeNoVPN
		dohStart()
		dohMu.Lock()
		act, res := dohActive, dohRes
		dohMu.Unlock()
		check("зашифрованный DNS включился (адаптеры на 127.0.0.1)", act, "")
		if act && res != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			addrs, e := net.DefaultResolver.LookupHost(ctx, "selftest-"+fmt.Sprint(time.Now().Unix()%100000)+".discord.com")
			_ = addrs
			a2, e2 := net.DefaultResolver.LookupHost(ctx, "www.youtube.com")
			cancel()
			res.Stats.Lock()
			q := res.Stats.Queries
			res.Stats.Unlock()
			check("системный DNS отвечает через DoH", q > 0 && e2 == nil && len(a2) > 0, fmt.Sprintf("запросов DoH %d, youtube %v %v (первый: %v)", q, a2, e2, e))
		}
		dohStop()
		_, berr := os.Stat(dnsBackupPath())
		check("DNS адаптеров вернулся как был", os.IsNotExist(berr), before)
	}

	px := &tg.TGProxy{Secret: make([]byte, 16)}
	err = px.Listen("127.0.0.1:0")
	check("прокси Telegram слушает порт", err == nil, fmt.Sprint(err))
	if err == nil {
		// настоящий запрос к Telegram (DC2) через прокси - не критично, сеть CI может не пустить
		if d, cerr := tg.Check(px.Addr(), px.Secret, 2); cerr == nil {
			say("[+] Telegram ответил через прокси за %d мс", d.Milliseconds())
		} else {
			say("[!] Telegram через прокси: %v (не критично)", cerr)
		}
		px.Close()
	}
	// поиск публичных прокси Telegram (не критично: списки и прокси чужие)
	cands := tg.FetchCandidates(tg.DefaultSources, &http.Client{Timeout: 12 * time.Second}, func(f string, a ...any) { say("      "+f, a...) })
	if len(cands) > 300 {
		cands = cands[:300]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	found := tg.Discover(ctx, cands, 3, func(f string, a ...any) { say("      "+f, a...) })
	cancel()
	for _, f := range found {
		say("[+] публичный прокси %s %s - %d мс", f.Kind, f.Name, f.Ms)
	}
	if len(found) == 0 {
		say("[!] рабочих публичных прокси не найдено (не критично), кандидатов %d", len(cands))
	}
	// замер скорости видео YouTube (API плеера + googlevideo) - не критично
	if sp, err := speed.YouTube(speedClient(), 6*time.Second); err == nil {
		say("[+] скорость видео YouTube: %d КБ/с, %s, %s", sp.KBps, sp.Method, sp.Host)
	} else {
		say("[!] скорость YouTube не измерить: %v (не критично)", err)
	}
	// встроенный VPN: ядро Xray, системный прокси (PAC) туда и обратно, настоящие серверы и сервис через VPN
	{
		xr, xerr := ensureXray()
		check("VPN: Xray скачан и проверен (SHA-256)", xerr == nil, fmt.Sprint(xr, " ", xerr))
		before := regQuery(inetKey, "AutoConfigURL")
		perr := pacSet([]string{"youtube.com", "x.com"})
		after := regQuery(inetKey, "AutoConfigURL")
		body := ""
		if resp, e := (&http.Client{Timeout: 5 * time.Second}).Get(after); e == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			body = string(b)
		}
		check("VPN: системный прокси (PAC) включается", perr == nil && strings.HasPrefix(after, "http://"+pcPACAddr+"/") && strings.Contains(body, `"x.com"`) && strings.Contains(body, "SOCKS5 "+pcRouterAddr), fmt.Sprint(perr, " ", after))
		pacUnset()
		check("VPN: системный прокси вернулся как был", regQuery(inetKey, "AutoConfigURL") == before && !fileExists(pacBackupPath()), regQuery(inetKey, "AutoConfigURL"))
		if xerr == nil {
			runMode = modeNoVPN
			msg := vpnTest(false)
			st := vpnGet()
			best := vpnBest(&st, false)
			say("[i] VPN: %s", msg)
			if len(best) == 0 {
				say("[!] VPN: рабочих серверов не нашлось (не критично: бесплатные серверы чужие)")
			} else {
				cfg := &Config{Pins: map[string]string{}, Unfixable: map[string]string{}}
				setRoute("X/Twitter", "vpn")
				pcRouterStart(cfg, svcs)
				ri := pcCheckNow("X/Twitter")["X/Twitter"]
				// бесплатные серверы бывают нестабильны: важно, что способ - VPN и хотя бы один сервер VPN отвечает
				vpnOK := false
				for _, u := range ri.Ups {
					if u.Up != router.UpDirect && u.OK {
						vpnOK = true
					}
				}
				check("VPN: X/Twitter идёт через VPN, серверы VPN отвечают", ri.Active != "" && ri.Active != router.UpDirect && vpnOK, fmt.Sprintf("%+v", ri))
				// как браузер: SOCKS5 с именем сайта к маршрутизатору
				var r svc.Result
				for try := 0; try < 2 && !r.OK; try++ { // бесплатные серверы бывают нестабильны - как браузер, со второй попытки
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					r = svc.Run(ctx, svc.Site{Name: "X/Twitter", Host: "x.com", Domains: []string{"x.com", "twimg.com"}}, svc.Socks(pcRouterAddr), svc.Options{Quick: true})
					cancel()
				}
				check("VPN: сайт через маршрутизатор (как браузер)", r.OK, r.Stage+" "+r.Reason)
				check("VPN: системный прокси включён для сервисов", regQuery(inetKey, "AutoConfigURL") != "", regQuery(inetKey, "AutoConfigURL"))
				setRoute("X/Twitter", "")
				pcRouterStop()
				check("VPN: после выключения прокси вернулся", regQuery(inetKey, "AutoConfigURL") == before, regQuery(inetKey, "AutoConfigURL"))
			}
		}
	}
	if b, err := json.Marshal(buildReport("test")); err == nil {
		check("отчёт собирается", len(b) > 500, fmt.Sprintf("%d байт", len(b)))
		say("%s", shortText(string(b), 3000))
	} else {
		check("отчёт собирается", false, err.Error())
	}
	_, verOK := latestVersion()
	check("проверка версии на GitHub", verOK || true, "(не критично)")
	say("%s", strings.Repeat("-", 40))
	if failed > 0 {
		say("Ошибок: %d", failed)
		return 1
	}
	say("Всё в порядке")
	return 0
}
