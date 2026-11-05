//go:build windows

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const version = "1.2"

var (
	baseDir string
	dataDir string
	zapDir  string
)

type Group struct {
	Strategy string   `json:"strategy"`
	Services []string `json:"services"`
}

type Config struct {
	Created   time.Time         `json:"created"`
	Groups    []Group           `json:"groups"`
	Best      string            `json:"best"`
	NoUDPX    bool              `json:"no_udp_extras"`
	Unfixable map[string]string `json:"unfixable"`
	DNSBad    []string          `json:"dns_bad"`
	Expected  []string          `json:"expected"` // сервисы, которые должны работать
}

func cfgPath() string { return filepath.Join(dataDir, "config.json") }

func loadConfig() *Config {
	b, err := os.ReadFile(cfgPath())
	if err != nil {
		return nil
	}
	var c Config
	if json.Unmarshal(b, &c) != nil {
		return nil
	}
	return &c
}

func saveConfig(c *Config) {
	b, _ := json.MarshalIndent(c, "", "  ")
	os.WriteFile(cfgPath(), b, 0644)
}

func main() {
	initConsole()
	exe, _ := os.Executable()
	baseDir = filepath.Dir(exe)
	dataDir = filepath.Join(baseDir, "dpi-bypass-data")
	zapDir = filepath.Join(dataDir, "zapret-winws")

	cmd := ""
	if len(os.Args) > 1 {
		cmd = strings.ToLower(strings.TrimLeft(os.Args[1], "-/"))
	}
	if cmd == "help" || cmd == "h" || cmd == "?" {
		usage()
		return
	}
	if !isAdmin() {
		say("Нужны права администратора (для драйвера WinDivert) - запрашиваю...")
		if err := relaunchAsAdmin(os.Args[1:]); err != nil {
			bad("Не удалось перезапуститься от администратора: %v", err)
			say("Запусти dpi-bypass.exe правой кнопкой -> «Запуск от имени администратора».")
			pause()
			os.Exit(1)
		}
		return
	}

	banner()
	os.MkdirAll(dataDir, 0755)
	initJob()
	go handleSignals()

	switch cmd {
	case "":
		menu()
	case "1", "on", "nvpn", "novpn":
		startBypass(modeNoVPN, false)
	case "2", "vpn":
		startBypass(modeWithVPN, false)
	case "3", "off", "stop":
		shutdownAll()
		pause()
	case "4", "check":
		diagnostics()
		pause()
	case "auto":
		startBypass(modeWithVPN, true)
	case "telegram", "tg":
		openTGLink = true
		startBypass(modeWithVPN, false)
	case "reset":
		os.Remove(cfgPath())
		os.Remove(filepath.Join(dataDir, "lists", "auto-hostlist.txt"))
		good("Настройки удалены. При следующем запуске стратегии подберутся заново.")
		pause()
	default:
		bad("Неизвестная команда: %s\n", cmd)
		usage()
		pause()
	}
}

const (
	modeNoVPN   = 1 // обход без VPN (VPN выключается)
	modeWithVPN = 2 // обход вместе с VPN
)

var runMode = modeWithVPN

func menu() {
	for {
		others := otherInstances()
		st := detectVPN()
		say("")
		switch {
		case len(others) > 0:
			say("  Обход сейчас: %s", col(cGreen, "включён (в другом окне)"))
		case runningProcesses()["winws.exe"]:
			say("  Обход сейчас: %s", col(cYellow, "работает winws без программы"))
		default:
			say("  Обход сейчас: %s", col(cGray, "выключен"))
		}
		if st.Active() {
			say("  VPN:          %s", col(cYellow, firstNonEmpty(strings.Join(st.Procs, ", "), strings.Join(st.TunNames, ", "))+" ("+st.Mode()+")"))
		} else {
			say("  VPN:          не найден")
		}
		say("")
		say("  %s  Включить обход (VPN будет выключен)", col(cBold+cCyan, "1"))
		say("  %s  Включить обход вместе с VPN", col(cBold+cCyan, "2"))
		say("  %s  Выключить обход и завершить всё", col(cBold+cCyan, "3"))
		say("  %s  Диагностика (сайты, VPN, сеть)", col(cBold+cCyan, "4"))
		say("  %s  Подобрать стратегии заново", col(cBold+cCyan, "5"))
		say("  %s  Выход", col(cBold+cCyan, "0"))
		fmt.Print("\n  Выбери [1-5, 0]: ")
		switch strings.TrimSpace(readLine()) {
		case "1":
			startBypass(modeNoVPN, false)
			return
		case "2":
			startBypass(modeWithVPN, false)
			return
		case "3":
			shutdownAll()
			pause()
			return
		case "4":
			diagnostics()
		case "5":
			startBypass(modeWithVPN, true)
			return
		case "0", "q":
			return
		default:
			warn("Нужно ввести цифру 1, 2, 3, 4, 5 или 0")
		}
	}
}

var stdin = bufio.NewReader(os.Stdin)

func readLine() string {
	l, _ := stdin.ReadString('\n')
	return strings.TrimSpace(l)
}

func askYes(q string) bool {
	fmt.Printf("%s %s ", col(cYellow, "[?]"), q+" [Enter - да / n - нет]:")
	a := strings.ToLower(readLine())
	return a == "" || a == "y" || a == "д" || a == "да" || a == "yes"
}

// otherInstances - другие запущенные копии этой программы
func otherInstances() []uint32 {
	exe, _ := os.Executable()
	me := strings.ToLower(filepath.Base(exe))
	var res []uint32
	for _, p := range listProcesses() {
		if strings.ToLower(p.Exe) == me && p.PID != uint32(os.Getpid()) {
			res = append(res, p.PID)
		}
	}
	return res
}

func killPIDs(pids []uint32) int {
	n := 0
	for _, pid := range pids {
		h, err := syscall.OpenProcess(0x0001, false, pid)
		if err != nil {
			continue
		}
		if syscall.TerminateProcess(h, 0) == nil {
			n++
		}
		syscall.CloseHandle(h)
	}
	return n
}

// stopOthers останавливает обход, запущенный в других окнах
func stopOthers() {
	if n := killPIDs(otherInstances()); n > 0 {
		info("Остановил обход, запущенный в другом окне")
		time.Sleep(time.Second)
	}
	killStrayWinws()
}

func shutdownAll() {
	title("Выключение")
	stopOthers()
	stopActive()
	for _, args := range [][]string{{"stop", "windivert"}, {"delete", "windivert"}} {
		c := exec.Command("sc", args...)
		c.SysProcAttr = hiddenProcAttr()
		c.Run()
	}
	good("Обход выключен, драйвер WinDivert выгружен. Интернет работает как обычно.")
	if fileExists(tgSecretFile()) {
		say("%s", col(cGray, "      Если в Telegram включён прокси 127.0.0.1 - выключи его: Настройки -> Продвинутые ->"))
		say("%s", col(cGray, "      Тип соединения -> Без прокси (иначе Telegram не подключится)."))
	}
}

func diagnostics() {
	svcs := mustPrepare()
	printVPNDetails()
	vpnStep()
	diagnose(svcs)
}

func startBypass(mode int, reselect bool) {
	runMode = mode
	stopOthers()
	svcs := mustPrepare()
	checkConflicts()
	if mode == modeNoVPN {
		title("Режим: обход без VPN")
		if v := detectVPN(); v.Active() {
			warn("Найден VPN: %s (%s)", firstNonEmpty(strings.Join(v.Procs, ", "), strings.Join(v.TunNames, ", ")), v.Mode())
			if askYes("Закрыть его?") {
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
	var cfg *Config
	if !reselect {
		cfg = loadConfig()
	}
	if cfg != nil {
		info("Найдены сохранённые настройки от %s", cfg.Created.Format("02.01.2006 15:04"))
	} else {
		cfg = selectConfig(svcs)
	}
	runForever(cfg, svcs)
}

var openTGLink bool

func vpnStep() {
	title("Проверка VPN")
	curVPN = detectVPN()
	applyVPN(curVPN)
	printVPN(curVPN)
}

func handleSignals() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	say("\n")
	info("Останавливаю обход...")
	stopActive()
	good("Остановлено. Интернет работает как обычно.")
	os.Exit(0)
}

func mustPrepare() []Service {
	if err := ensureZapret(); err != nil {
		bad("%v", err)
		say("\nМожно скачать вручную: github.com/bol-van/zapret-win-bundle -> папку zapret-winws")
		say("положи рядом с dpi-bypass.exe. Если файлы удаляет антивирус - добавь папку в исключения.")
		pause()
		os.Exit(1)
	}
	svcs, err := loadServices()
	if err != nil || len(svcs) == 0 {
		bad("Не удалось прочитать %s: %v", sitesPath(), err)
		pause()
		os.Exit(1)
	}
	return svcs
}

// ---------- диагностика ----------

func printTable(svcs []Service, res map[string]SvcResult) {
	for _, s := range svcs {
		r := res[s.Name]
		line := fmt.Sprintf("  [%s] %s", mark(r.OK), pad(s.Name, 11))
		if r.OK {
			line += col(cGreen, "доступен")
		} else {
			line += col(cRed, r.Reason)
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

func selectConfig(svcs []Service) *Config {
	base := diagnose(svcs)
	cfg := &Config{Created: time.Now(), Unfixable: map[string]string{}}

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

	title("Перебор стратегий (%d шт.)", len(strategies))
	works := map[string]map[string]bool{} // стратегия -> сервис -> работает
	for i, st := range strategies {
		fmt.Printf("  %s %-42s ", col(cGray, fmt.Sprintf("[%2d/%d]", i+1, len(strategies))), st.Name)
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
		if all {
			say("%s", col(cGreen, "      -> эта стратегия открывает всё, дальше можно не искать"))
			break
		}
	}

	if len(works) == 0 {
		bad("winws не запустился ни разу. Частые причины: антивирус заблокировал WinDivert64.sys,")
		bad("или запущен другой обходчик (GoodbyeDPI и т.п.). Добавь папку %s в исключения.", dataDir)
		pause()
		os.Exit(1)
	}

	// жадно покрываем сервисы минимальным числом стратегий
	remaining := map[string]bool{}
	for _, s := range cands {
		remaining[s.Name] = true
	}
	for len(remaining) > 0 {
		bestID, bestN := "", 0
		for _, st := range strategies {
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
		cfg.Groups = append(cfg.Groups, g)
	}
	if len(cfg.Groups) > 0 {
		cfg.Best = cfg.Groups[0].Strategy
	}
	for _, s := range cands {
		if remaining[s.Name] {
			cfg.Unfixable[s.Name] = "ни одна стратегия не помогла (" + base[s.Name].Reason + ")"
		} else {
			cfg.Expected = append(cfg.Expected, s.Name)
		}
	}

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
		say(col(cGray, "      Блокировку по IP локально не обойти - для этих сайтов нужен VPN/прокси."))
	}
	if len(cfg.DNSBad) > 0 {
		warn("DNS провайдера подменяет ответы для: %s", strings.Join(cfg.DNSBad, ", "))
		say(col(cGray, "      Включи «Безопасный DNS» в браузере (Chrome/Edge/Firefox: Настройки -> Конфиденциальность"))
		say(col(cGray, "      -> Использовать безопасный DNS -> Cloudflare) или DNS-over-HTTPS в настройках Windows 11."))
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
	var out []Service
	for _, s := range svcs {
		if want[s.Name] {
			out = append(out, s)
		}
	}
	return out
}

func statusLine(svcs []Service, res map[string]SvcResult) string {
	var parts []string
	for _, s := range svcs {
		parts = append(parts, fmt.Sprintf("%s %s", mark(res[s.Name].OK), s.Name))
	}
	return strings.Join(parts, "  ")
}

func runForever(cfg *Config, svcs []Service) {
	loadTGWorker()
	title("Запуск обхода")
	w, err := startCombined(cfg, svcs)
	if err != nil {
		bad("%v", err)
		warn("Пробую подобрать стратегии заново...")
		cfg = selectConfig(svcs)
		if w, err = startCombined(cfg, svcs); err != nil {
			bad("%v", err)
			pause()
			os.Exit(1)
		}
	}

	exp := expectedServices(cfg, svcs)
	if len(exp) > 0 {
		info("Проверяю итоговую конфигурацию...")
		res := probeAll(exp)
		say("  %s", statusLine(exp, res))
		broken := 0
		for _, s := range exp {
			if !res[s.Name].OK {
				broken++
			}
		}
		if broken*2 > len(exp) {
			warn("Сохранённая стратегия больше не работает - подбираю заново.")
			w.Stop()
			cfg = selectConfig(svcs)
			if w, err = startCombined(cfg, svcs); err != nil {
				bad("%v", err)
				pause()
				os.Exit(1)
			}
			exp = expectedServices(cfg, svcs)
		}
	}

	writeDirectList(cfg, svcs)
	startTelegram(openTGLink, cfg)

	say("")
	good("%s Не закрывай это окно. Ctrl+C - выключить.", col(cBold, "Обход работает."))
	say(col(cGray, "     Сервисы проверяются раз в минуту; если что-то отвалится - стратегия подберётся заново."))

	fails := map[string]int{}
	lastReselect := time.Now()
	last, lastTG := "", ""
	for {
		time.Sleep(60 * time.Second)

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
			w.Stop()
			if w, err = startCombined(cfg, svcs); err != nil {
				bad("%v", err)
				continue
			}
			fails = map[string]int{}
		}
		tgWatch()
		if l := tgStatusLine(); l != "" && l != lastTG {
			info("%s %s", ts(), l)
			lastTG = l
		}

		if !w.Alive() {
			warn("%s winws неожиданно завершился: %s - перезапускаю", ts(), w.out.Tail())
			if w, err = startCombined(cfg, svcs); err != nil {
				bad("%v", err)
				continue
			}
		}
		if len(exp) == 0 {
			continue
		}
		res := probeAll(exp)
		line := statusLine(exp, res)
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
			cfg = selectConfig(svcs)
			lastReselect = time.Now()
			fails = map[string]int{}
			exp = expectedServices(cfg, svcs)
			if w, err = startCombined(cfg, svcs); err != nil {
				bad("%v", err)
				pause()
				os.Exit(1)
			}
			good("%s Обход снова работает.", ts())
		}
	}
}
