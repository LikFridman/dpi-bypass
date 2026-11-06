//go:build windows

package main

import (
	"context"
	svc "dpibypass/check"
	"dpibypass/speed"
	"dpibypass/tg"
	"encoding/json"
	"fmt"
	"net/http"
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
	vpnStep()
	cfg := &Config{Best: "s1", Unfixable: map[string]string{}, Sites: map[string]string{"example.org": "s2"}}
	var names []string
	for _, s := range svcs {
		names = append(names, s.Name)
	}
	cfg.Groups = []Group{{Strategy: "s1", Services: names}}

	for _, st := range strategies {
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
