//go:build windows

package main

// Глубокая проверка: для одного сайта перебираются сотни комбинаций параметров winws
// (как blockcheck из zapret). Долго, зато находит обход почти всегда, если блокировка - DPI.

import (
	"fmt"
	"strings"
	"time"
)

// deepScan ищет стратегию для одного сайта (winws должен быть остановлен). Возвращает найденную.
func deepScan(host string) (Strategy, bool) {
	title("Глубокая проверка: %s", host)
	svc := Service{Name: host, Probes: []string{host}, Domains: []string{host}}
	r := probeService(svc)
	switch {
	case r.OK:
		good("%s открывается и без обхода.", host)
		return Strategy{}, false
	case r.Stage == StDNS || r.Stage == StTCP:
		bad("%s: %s. Это блокировка по IP/DNS - перебор параметров DPI тут не поможет.", host, r.Reason)
		return Strategy{}, false
	}
	info("Без обхода: %s", r.Reason)

	// сначала обычные стратегии - вдруг хватит их
	combos := append(append([]Strategy{}, orderedStrategies()...), deepCombos()...)
	total := len(combos)
	info("Комбинаций: %d. Это может занять 10-30 минут - кнопка «Стоп» прервёт.", total)

	oldDial, oldTotal := dialTO, totalTO
	dialTO, totalTO = 4*time.Second, 6*time.Second
	defer func() { dialTO, totalTO = oldDial, oldTotal }()

	start := time.Now()
	progTotal.Store(int64(total))
	defer progTotal.Store(0)
	for i, st := range combos {
		progCur.Store(int64(i + 1))
		if cancelled() {
			fail("Глубокая проверка остановлена.")
		}
		if i%10 == 0 || i == total-1 {
			el := time.Since(start)
			left := ""
			if i > 0 {
				left = fmt.Sprintf(", осталось ~%d мин", int(el.Seconds()/float64(i)*float64(total-i)/60)+1)
			}
			setStatus(fmt.Sprintf("Глубокая проверка %s: %d из %d%s", host, i+1, total, left))
			info("[%d/%d] проверяю...%s", i+1, total, left)
		}
		w, err := startWinws(testArgs(st))
		if err != nil {
			continue
		}
		ok := probeService(svc).OK
		if ok {
			// перепроверяем дважды - случайный успех не нужен
			ok = probeService(svc).OK && probeService(svc).OK
		}
		w.Stop()
		if ok {
			good("Нашлась рабочая комбинация (%d/%d): %s", i+1, total, st.Name)
			say("      %s", strings.Join(st.Args, " "))
			return st, true
		}
	}
	bad("Ни одна из %d комбинаций не открыла %s.", total, host)
	say("      Скорее всего, тут не DPI, а блокировка на уровне IP или самого сайта - нужен VPN.")
	return Strategy{}, false
}

// deepScanStandalone - запуск из меню/окна. target пустой - все неоткрывшиеся сервисы.
func deepScanStandalone(target string) {
	svcs := mustPrepare()
	stopOthers()
	if !curVPN.Active() && curVPN.PhysIdx == 0 {
		vpnStep()
	}
	cfg := loadConfig()
	if cfg == nil {
		cfg = &Config{Created: time.Now(), Unfixable: map[string]string{}}
	}
	var hosts []string
	target = strings.ToLower(strings.TrimSpace(target))
	target = strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	if i := strings.IndexAny(target, "/:"); i >= 0 {
		target = target[:i]
	}
	if target != "" {
		hosts = []string{target}
	} else {
		for _, s := range svcs {
			if r, bad := cfg.Unfixable[s.Name]; bad && !strings.Contains(r, "TCP") && !strings.Contains(r, "DNS") {
				hosts = append(hosts, s.Probes[0])
			}
		}
		if len(hosts) == 0 {
			info("Нет сайтов, которые не открылись из-за DPI. Укажи сайт вручную.")
			return
		}
	}
	if cfg.Sites == nil {
		cfg.Sites = map[string]string{}
	}
	for _, h := range hosts {
		st, ok := deepScan(h)
		if !ok {
			continue
		}
		if !strings.HasPrefix(st.ID, "s") && !strings.HasPrefix(st.ID, "u-") {
			st.ID = fmt.Sprintf("c%d", time.Now().UnixNano()%1000000)
			st.Name = "найдено глубокой проверкой: " + st.Name
			cfg.Custom = append(cfg.Custom, st)
			registerCustom([]Strategy{st})
		}
		// домен второго уровня, чтобы покрыть поддомены
		cfg.Sites[registrable(h)] = st.ID
		for _, s := range svcs {
			if _, was := cfg.Unfixable[s.Name]; was && domainCovered(h, s.Domains) {
				delete(cfg.Unfixable, s.Name)
				cfg.Expected = append(cfg.Expected, s.Name)
			}
		}
		saveConfig(cfg)
		good("Сохранено: %s теперь открывается своей стратегией. Включи обход заново, чтобы применить.", h)
	}
}

// registrable - упрощённо: последние две части домена (www.rutracker.org -> rutracker.org)
func registrable(h string) string {
	p := strings.Split(h, ".")
	if len(p) <= 2 {
		return h
	}
	last2 := p[len(p)-2] + "." + p[len(p)-1]
	// домены вида co.uk, com.ru - оставляем три части
	if len(p[len(p)-2]) <= 3 && len(p) >= 3 && (p[len(p)-2] == "co" || p[len(p)-2] == "com" || p[len(p)-2] == "org" || p[len(p)-2] == "net") {
		return p[len(p)-3] + "." + last2
	}
	return last2
}
