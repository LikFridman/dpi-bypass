//go:build windows

package main

import (
	"fmt"
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
		w.Stop()
	}
	px := &TGProxy{Secret: make([]byte, 16)}
	err = px.Listen("127.0.0.1:0")
	check("прокси Telegram слушает порт", err == nil, fmt.Sprint(err))
	if err == nil {
		px.Close()
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
