//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- управление обходом (запуск/остановка без выхода из программы) ----------

type engineRun struct {
	stop chan struct{}
	done chan struct{}
	once sync.Once
	tune chan struct{}
}

var (
	engMu      sync.Mutex
	eng        *engineRun
	engRunning atomic.Bool
	cancelFlag atomic.Bool
	statusHook func(string) // окно подписывается на смену статуса
	statusText atomic.Value
)

func setStatus(s string) {
	statusText.Store(s)
	if statusHook != nil {
		statusHook(s)
	}
}

func cancelled() bool { return cancelFlag.Load() }

// stopEngine останавливает обход в этой программе и ждёт завершения
func stopEngine() {
	engMu.Lock()
	e := eng
	engMu.Unlock()
	if e == nil {
		return
	}
	cancelFlag.Store(true)
	e.once.Do(func() { close(e.stop) })
	select {
	case <-e.done:
	case <-time.After(60 * time.Second):
	}
	cancelFlag.Store(false)
}

// requestTune просит работающий обход подобрать стратегии для новых сайтов
func requestTune() bool {
	engMu.Lock()
	e := eng
	engMu.Unlock()
	if e == nil || !engRunning.Load() {
		return false
	}
	select {
	case e.tune <- struct{}{}:
	default:
	}
	return true
}

func startBypass(mode int, reselect bool) {
	stopEngine()
	e := &engineRun{stop: make(chan struct{}), done: make(chan struct{}), tune: make(chan struct{}, 1)}
	engMu.Lock()
	eng = e
	engMu.Unlock()
	defer func() {
		close(e.done)
		engMu.Lock()
		if eng == e {
			eng = nil
		}
		engMu.Unlock()
	}()

	runMode = mode
	settings.LastMode = mode
	saveSettings()
	setStatus("Starting…")
	stopOthers()
	svcs := mustPrepare()
	checkConflicts()
	if mode == modeNoVPN {
		title("Режим: обход без VPN")
		if v := detectVPN(); v.Active() {
			warn("Найден VPN: %s", vpnTitle(v))
			if askYes("Найден VPN: " + vpnTitle(v) + ".\nЗакрыть его?") {
				stopVPN(v)
				time.Sleep(2 * time.Second)
				if v2 := detectVPN(); len(v2.TunNames) > 0 {
					warn("VPN-туннель всё ещё активен (%s) - выключи его в самом VPN-клиенте.", strings.Join(v2.TunNames, ", "))
					say("%s", col(cGray, "      Пока он включён, обход будет работать в безопасном режиме и не тронет VPN."))
				}
			}
		}
	} else {
		title("Режим: обход вместе с VPN")
	}
	vpnStep()
	if mode == modeWithVPN && !curVPN.Active() {
		info("Сейчас VPN не включён. Когда включишь - программа сама подстроится (проверка раз в минуту).")
	}
	showISP()
	var cfg *Config
	if !reselect {
		cfg = loadConfig()
	}
	if cfg != nil {
		info("Найдены сохранённые настройки от %s", cfg.Created.Format("02.01.2006 15:04"))
		if isp := currentISP(); cfg.ISP != "" && isp.ASN != "" && cfg.ISP != isp.ASN {
			warn("Сменился провайдер (%s -> %s) - подбираю стратегии для нового.", cfg.ISP, isp.ASN)
			cfg = selectConfig(svcs, cfg)
		}
	} else {
		cfg = selectConfig(svcs, nil)
	}
	runForever(cfg, svcs, e)
}

// ---------- диагностика ----------

func printTable(svcs []Service, res map[string]SvcResult) {
	for _, s := range svcs {
		r := res[s.Name]
		line := fmt.Sprintf("  [%s] %s", mark(r.OK), pad(s.Name, 11))
		if r.OK {
			line += col(cGreen, "ping "+pingLabel(r))
		} else {
			line += col(cRed, "ping none") + " · " + r.Reason
		}
		if r.DNSBad {
			line += col(cYellow, "  (+ DNS провайдера врёт)")
		}
		say("%s", line)
	}
}

func diagnose(svcs []Service) map[string]SvcResult {
	title("Проверка без обхода")
	info("Определяю IP, TCP, TLS и загрузку данных для %d сервисов...", len(svcs))
	res := probeAll(svcs)
	printTable(svcs, res)
	return res
}

// ---------- подбор стратегий ----------

// testStrategies проверяет стратегии по очереди; stopWhenAll - остановиться, когда всё открылось.
// Возвращает: стратегия -> сервис -> работает.
func testStrategies(list []Strategy, cands []Service, stopWhenAll bool) map[string]map[string]bool {
	works := map[string]map[string]bool{}
	for i, st := range list {
		if cancelled() {
			fail("Отменено.")
		}
		setStatus(fmt.Sprintf("Testing strategies: %d/%d", i+1, len(list)))
		fmt.Fprintf(out, "  %s %-42s ", col(cGray, fmt.Sprintf("[%2d/%d]", i+1, len(list))), st.Name)
		w, err := startWinws(testArgs(st))
		if err != nil {
			say("%s", col(cYellow, "не запустилась"))
			if i == 0 {
				say("%s", col(cGray, "      "+strings.ReplaceAll(err.Error(), "\n", "\n      ")))
			}
			continue
		}
		res := probeAll(cands)
		w.Stop()
		works[st.ID] = map[string]bool{}
		all := true
		var parts []string
		for _, s := range cands {
			ok := res[s.Name].OK
			works[st.ID][s.Name] = ok
			all = all && ok
			parts = append(parts, fmt.Sprintf("%s %s", mark(ok), s.Name))
		}
		say("%s", strings.Join(parts, "  "))
		if all && stopWhenAll {
			say("%s", col(cGreen, "      -> эта стратегия открывает всё, дальше можно не искать"))
			break
		}
	}
	if len(works) == 0 {
		bad("winws не запустился ни разу. Частые причины: антивирус заблокировал WinDivert64.sys,")
		fail("или запущен другой обходчик (GoodbyeDPI и т.п.). Пункт «Защитник» поможет.")
	}
	return works
}

// coverGroups жадно покрывает сервисы минимальным числом стратегий
func coverGroups(list []Strategy, cands []Service, works map[string]map[string]bool) ([]Group, map[string]bool) {
	remaining := map[string]bool{}
	for _, s := range cands {
		remaining[s.Name] = true
	}
	var groups []Group
	for len(remaining) > 0 {
		bestID, bestN := "", 0
		for _, st := range list {
			n := 0
			for name := range remaining {
				if works[st.ID][name] {
					n++
				}
			}
			if n > bestN {
				bestID, bestN = st.ID, n
			}
		}
		if bestN == 0 {
			break
		}
		g := Group{Strategy: bestID}
		for _, s := range cands {
			if remaining[s.Name] && works[bestID][s.Name] {
				g.Services = append(g.Services, s.Name)
				delete(remaining, s.Name)
			}
		}
		groups = append(groups, g)
	}
	return groups, remaining
}

// selectConfig подбирает стратегии; prev - старые настройки (свои стратегии для сайтов сохраняются)
func selectConfig(svcs []Service, prev *Config) *Config {
	setStatus("Checking sites…")
	base := diagnose(svcs)
	cfg := &Config{Created: time.Now(), Unfixable: map[string]string{}, ISP: currentISP().ASN}
	if prev != nil {
		cfg.Sites, cfg.Custom, cfg.Tuned = prev.Sites, prev.Custom, prev.Tuned
	}

	var cands []Service
	for _, s := range svcs {
		r := base[s.Name]
		if r.DNSBad {
			cfg.DNSBad = append(cfg.DNSBad, s.Name)
		}
		switch {
		case r.OK:
			cfg.Expected = append(cfg.Expected, s.Name)
		case r.Stage == StDNS || r.Stage == StTCP:
			cfg.Unfixable[s.Name] = r.Reason
		default:
			cands = append(cands, s)
		}
	}

	if len(cands) == 0 {
		title("Итог")
		if len(cfg.Unfixable) == 0 {
			good("DPI-блокировок среди сервисов из списка не найдено.")
		}
		info("Включаю универсальный режим: сайты, которые начнут блокироваться, обойдутся автоматически.")
		finishReport(cfg)
		saveConfig(cfg)
		writeDirectList(cfg, svcs)
		return cfg
	}

	list := orderedStrategies()
	title("Перебор стратегий (%d шт.)", len(list))
	works := testStrategies(list, cands, true)
	groups, remaining := coverGroups(list, cands, works)
	cfg.Groups = groups
	if len(cfg.Groups) > 0 {
		cfg.Best = cfg.Groups[0].Strategy
	}
	for _, s := range cands {
		if remaining[s.Name] {
			cfg.Unfixable[s.Name] = "ни одна стратегия не помогла (" + base[s.Name].Reason + ") - попробуй глубокую проверку"
		} else {
			cfg.Expected = append(cfg.Expected, s.Name)
		}
	}
	var used []string
	for _, g := range cfg.Groups {
		used = append(used, g.Strategy)
	}
	recordISPResult(used)

	title("Итог подбора")
	for _, g := range cfg.Groups {
		st, _ := strategyByID(g.Strategy)
		good("%s  ->  %s", strings.Join(g.Services, ", "), st.Name)
	}
	finishReport(cfg)
	saveConfig(cfg)
	writeDirectList(cfg, svcs)
	return cfg
}

func finishReport(cfg *Config) {
	names := make([]string, 0, len(cfg.Unfixable))
	for n := range cfg.Unfixable {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		bad("%s: %s", n, cfg.Unfixable[n])
	}
	if len(names) > 0 {
		say("%s", col(cGray, "      Блокировку по IP локально не обойти - для таких сайтов нужен VPN/прокси."))
	}
	if len(cfg.DNSBad) > 0 {
		warn("DNS провайдера подменяет ответы для: %s", strings.Join(cfg.DNSBad, ", "))
		say("%s", col(cGray, "      Включи «Безопасный DNS» в браузере (Chrome/Edge/Firefox: Настройки -> Конфиденциальность"))
		say("%s", col(cGray, "      -> Использовать безопасный DNS -> Cloudflare) или DNS-over-HTTPS в настройках Windows 11."))
	}
}

// ---------- работа + сторож ----------

func startCombined(cfg *Config, svcs []Service) (*Winws, error) {
	args, err := buildArgs(cfg, svcs, !cfg.NoUDPX)
	if err != nil {
		return nil, err
	}
	w, err := startWinws(args)
	if err != nil && !cfg.NoUDPX {
		// старые/иные сборки winws могут не знать фильтры discord/stun - пробуем без них
		args, _ = buildArgs(cfg, svcs, false)
		if w, err2 := startWinws(args); err2 == nil {
			cfg.NoUDPX = true
			saveConfig(cfg)
			return w, nil
		}
	}
	return w, err
}

func expectedServices(cfg *Config, svcs []Service) []Service {
	want := map[string]bool{}
	for _, n := range cfg.Expected {
		want[n] = true
	}
	var res []Service
	for _, s := range svcs {
		if want[s.Name] {
			res = append(res, s)
		}
	}
	return res
}

func statusLine(svcs []Service, res map[string]SvcResult) string {
	var parts []string
	for _, s := range svcs {
		parts = append(parts, fmt.Sprintf("%s %s", mark(res[s.Name].OK), s.Name))
	}
	return strings.Join(parts, "  ")
}

func plainStatus(svcs []Service, res map[string]SvcResult) string {
	ok, total := 0, len(svcs)
	var bad []string
	for _, s := range svcs {
		if res[s.Name].OK {
			ok++
		} else {
			bad = append(bad, s.Name)
		}
	}
	m := map[int]string{modeNoVPN: "no VPN", modeWithVPN: "with VPN"}[runMode]
	s := fmt.Sprintf("Running (%s): %d/%d up", m, ok, total)
	if p := avgPing(res); p > 0 {
		s += fmt.Sprintf(" · ping ~%d ms", p)
	}
	if len(bad) > 0 {
		s += " · none: " + strings.Join(bad, ", ")
	}
	return s
}

func runForever(cfg *Config, svcs []Service, e *engineRun) {
	loadTGWorker()
	title("Запуск обхода")
	w, err := startCombined(cfg, svcs)
	if err != nil {
		bad("%v", err)
		warn("Пробую подобрать стратегии заново...")
		cfg = selectConfig(svcs, cfg)
		if w, err = startCombined(cfg, svcs); err != nil {
			fail("%v", err)
		}
	}
	engRunning.Store(true)
	publishCfg(cfg)
	defer func() {
		engRunning.Store(false)
		clearResults()
		w.Stop()
		stopTelegram()
		setStatus("Bypass off")
	}()

	exp := expectedServices(cfg, svcs)
	if len(exp) > 0 {
		info("Проверяю итоговую конфигурацию...")
		res := probeAll(exp)
		publishResults(res)
		say("  %s", statusLine(exp, res))
		setStatus(plainStatus(exp, res))
		broken := 0
		for _, s := range exp {
			if !res[s.Name].OK {
				broken++
			}
		}
		if broken*2 > len(exp) {
			warn("Сохранённая стратегия больше не работает - подбираю заново.")
			w.Stop()
			cfg = selectConfig(svcs, cfg)
			if w, err = startCombined(cfg, svcs); err != nil {
				fail("%v", err)
			}
			exp = expectedServices(cfg, svcs)
			publishCfg(cfg)
		}
	} else {
		setStatus(plainStatus(exp, nil))
	}

	writeDirectList(cfg, svcs)
	startTelegram(openTGLink, cfg)

	say("")
	if guiMode {
		good("%s Окно можно свернуть - обход продолжит работать.", col(cBold, "Обход работает."))
	} else {
		good("%s Не закрывай это окно. Ctrl+C - выключить.", col(cBold, "Обход работает."))
	}
	say("%s", col(cGray, "     Сервисы проверяются раз в минуту; если что-то отвалится - стратегия подберётся заново."))

	// перезапуск winws с проверкой (после подбора/изменений)
	restart := func() {
		w.Stop()
		if w, err = startCombined(cfg, svcs); err != nil {
			bad("%v", err)
		}
	}
	// подбор своих стратегий для новых заблокированных сайтов из автосписка
	tune := func(manual bool) {
		hosts := autoHosts(cfg, svcs)
		if len(hosts) == 0 {
			if manual {
				info("Новых заблокированных сайтов в автосписке нет.")
			}
			return
		}
		w.Stop()
		guard(func() { tuneHosts(cfg, hosts) })
		cfg.Tuned = time.Now()
		saveConfig(cfg)
		publishCfg(cfg)
		if w, err = startCombined(cfg, svcs); err != nil {
			bad("%v", err)
		}
	}

	fails := map[string]int{}
	lastReselect := time.Now()
	last, lastTG := "", ""
	for {
		select {
		case <-e.stop:
			info("Останавливаю обход...")
			return
		case <-e.tune:
			tune(true)
			continue
		case <-time.After(60 * time.Second):
		}

		// VPN включили/выключили/переподключили - перестраиваем обход
		if nv := detectVPN(); nv.Key() != curVPN.Key() {
			was := curVPN.Active()
			curVPN = nv
			applyVPN(nv)
			switch {
			case nv.Active() && !was:
				warn("%s Включился VPN - подстраиваюсь", ts())
			case !nv.Active() && was:
				warn("%s VPN выключен - обход снова на всём трафике", ts())
			default:
				info("%s Изменилось состояние VPN/сети - перезапускаю обход", ts())
			}
			printVPN(nv)
			restart()
			fails = map[string]int{}
		}
		tgWatch()
		if l := tgStatusLine(); l != "" && l != lastTG {
			info("%s %s", ts(), l)
			lastTG = l
		}

		if w == nil || !w.Alive() {
			if w != nil {
				warn("%s winws неожиданно завершился: %s - перезапускаю", ts(), w.out.Tail())
				explainWinwsExit(w.out.Tail())
			}
			if len(missingZapretFiles()) > 0 {
				if err := ensureZapret(); err != nil {
					bad("%v", err)
				}
			}
			if w, err = startCombined(cfg, svcs); err != nil {
				bad("%v", err)
				setStatus("Ошибка: winws не запускается - смотри журнал")
				continue
			}
		}

		// новые заблокированные сайты - не чаще раза в 30 минут
		if time.Since(cfg.Tuned) > 30*time.Minute && len(autoHosts(cfg, svcs)) > 0 {
			info("%s В автосписке появились новые заблокированные сайты - подбираю для них стратегии (обход прервётся на минуту)", ts())
			tune(false)
		}

		if len(exp) == 0 {
			continue
		}
		res := probeAll(exp)
		publishResults(res)
		line := statusLine(exp, res)
		setStatus(plainStatus(exp, res))
		need := false
		for _, s := range exp {
			if res[s.Name].OK {
				fails[s.Name] = 0
			} else if fails[s.Name]++; fails[s.Name] >= 2 {
				need = true
			}
		}
		if line != last || need {
			say("%s  %s", ts(), line)
			last = line
		}
		if need && time.Since(lastReselect) > 10*time.Minute {
			warn("%s Сервисы перестали открываться - провайдер поменял блокировку, подбираю заново", ts())
			w.Stop()
			ok := guard(func() { cfg = selectConfig(svcs, cfg) })
			lastReselect = time.Now()
			fails = map[string]int{}
			exp = expectedServices(cfg, svcs)
			publishCfg(cfg)
			if w, err = startCombined(cfg, svcs); err != nil {
				fail("%v", err)
			}
			if ok {
				good("%s Обход снова работает.", ts())
			}
		}
	}
}

// ---------- свои стратегии для сайтов из автосписка ----------

func autoListFile() string { return filepath.Join(dataDir, "lists", "auto-hostlist.txt") }

func readHostList(p string) []string {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var res []string
	seen := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.ToLower(strings.TrimSpace(l))
		if l == "" || strings.HasPrefix(l, "#") || seen[l] {
			continue
		}
		seen[l] = true
		res = append(res, l)
	}
	return res
}

func domainCovered(host string, domains []string) bool {
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// autoHosts - сайты из автосписка winws, для которых ещё нет своей стратегии
func autoHosts(cfg *Config, svcs []Service) []string {
	var known []string
	for _, s := range svcs {
		known = append(known, s.Domains...)
	}
	for d := range cfg.Sites {
		known = append(known, d)
	}
	var res []string
	for _, h := range readHostList(autoListFile()) {
		if !domainCovered(h, known) {
			res = append(res, h)
		}
		if len(res) >= 15 {
			break
		}
	}
	return res
}

func removeFromAutoList(hosts []string) {
	drop := map[string]bool{}
	for _, h := range hosts {
		drop[h] = true
	}
	var keep []string
	for _, h := range readHostList(autoListFile()) {
		if !drop[h] {
			keep = append(keep, h)
		}
	}
	os.WriteFile(autoListFile(), []byte(strings.Join(keep, "\n")+"\n"), 0644)
}

// tuneHosts подбирает стратегию для каждого сайта отдельно (winws должен быть остановлен)
func tuneHosts(cfg *Config, hosts []string) {
	title("Подбор для новых сайтов (%d)", len(hosts))
	if cfg.Sites == nil {
		cfg.Sites = map[string]string{}
	}
	var svcs []Service
	for _, h := range hosts {
		svcs = append(svcs, Service{Name: h, Probes: []string{h}, Domains: []string{h}})
	}
	base := probeAll(svcs)
	var cands []Service
	var done []string
	for _, s := range svcs {
		r := base[s.Name]
		switch {
		case r.OK:
			info("%s открывается и без обхода - убираю из автосписка", s.Name)
			done = append(done, s.Name)
		case r.Stage == StDNS || r.Stage == StTCP:
			bad("%s: %s - обход DPI тут не поможет", s.Name, r.Reason)
			done = append(done, s.Name)
		default:
			cands = append(cands, s)
		}
	}
	if len(cands) > 0 {
		list := orderedStrategies()
		works := testStrategies(list, cands, true)
		groups, remaining := coverGroups(list, cands, works)
		for _, g := range groups {
			st, _ := strategyByID(g.Strategy)
			for _, h := range g.Services {
				cfg.Sites[h] = g.Strategy
				done = append(done, h)
			}
			good("%s  ->  %s", strings.Join(g.Services, ", "), st.Name)
		}
		for h := range remaining {
			warn("%s: ни одна стратегия не помогла - попробуй глубокую проверку", h)
		}
	}
	removeFromAutoList(done)
}

// tuneStandalone - подбор для новых сайтов, когда обход не запущен
func tuneStandalone() {
	if requestTune() {
		info("Подбор для новых сайтов запущен в работающем обходе.")
		return
	}
	svcs := mustPrepare()
	vpnStep()
	cfg := loadConfig()
	if cfg == nil {
		fail("Сначала включи обход - пока нет сохранённых настроек.")
	}
	hosts := autoHosts(cfg, svcs)
	if len(hosts) == 0 {
		info("Новых заблокированных сайтов в автосписке нет.")
		return
	}
	stopOthers()
	tuneHosts(cfg, hosts)
	cfg.Tuned = time.Now()
	saveConfig(cfg)
}
