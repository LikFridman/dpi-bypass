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
	"runtime/debug"
	"strings"
	"syscall"
	"time"
)

var version = "2.2" // при сборке на GitHub подставляется номер версии

var (
	baseDir string
	dataDir string
	zapDir  string
	guiMode bool // программа работает в окне (иначе - в консоли)
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
	ISP       string            `json:"isp,omitempty"`
	// свои стратегии для отдельных сайтов (подбор для автосписка и глубокая проверка)
	Sites  map[string]string `json:"sites,omitempty"` // домен -> id стратегии
	Custom []Strategy        `json:"custom,omitempty"`
	Pins   map[string]string `json:"pins,omitempty"` // закреплённые вручную: сервис -> стратегия
	Tuned  time.Time         `json:"tuned,omitempty"`
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
	registerCustom(c.Custom)
	return &c
}

func saveConfig(c *Config) {
	b, _ := json.MarshalIndent(c, "", "  ")
	os.WriteFile(cfgPath(), b, 0644)
}

// registerCustom добавляет найденные глубокой проверкой стратегии в общий список
func registerCustom(list []Strategy) {
	for _, s := range list {
		if _, ok := strategyByID(s.ID); !ok && validStrategy(s) {
			strategies = append(strategies, s)
		}
	}
}

// ---------- ошибки: в консоли - выход, в окне - отмена текущего действия ----------

type abortErr struct{}

func fail(format string, a ...any) {
	bad(format, a...)
	if msg := fmt.Sprintf(format, a...); !strings.Contains(msg, "Отменено") && !strings.Contains(msg, "остановлен") {
		tmError("%s", msg)
	}
	if guiMode {
		panic(abortErr{})
	}
	pause()
	os.Exit(1)
}

// guard выполняет действие и перехватывает fail(); возвращает false, если действие прервано
func guard(fn func()) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, isAbort := r.(abortErr); !isAbort {
				bad("Внутренняя ошибка: %v", r)
				tmError("внутренняя ошибка: %v\n%s", r, shortText(sanitizer().Replace(string(debug.Stack())), 4000))
			}
			ok = false
		}
	}()
	fn()
	return true
}

// ---------- запуск ----------

func main() {
	exe, _ := os.Executable()
	baseDir = filepath.Dir(exe)
	dataDir = filepath.Join(baseDir, "dpi-bypass-data")
	zapDir = filepath.Join(dataDir, "zapret-winws")
	cleanupOldExe()

	var args []string
	for _, a := range os.Args[1:] {
		args = append(args, strings.ToLower(strings.TrimLeft(a, "-/")))
	}
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	// без команды (двойной клик), из автозапуска и после обновления - окно
	guiMode = cmd == "" || cmd == "autostart" || cmd == "uitest" || strings.HasPrefix(cmd, "resume")
	if !guiMode {
		attachConsole(cmd == "console")
	}
	initConsole()

	if cmd == "help" || cmd == "h" || cmd == "?" {
		usage()
		return
	}
	if !isAdmin() {
		if !guiMode {
			say("Нужны права администратора (для драйвера WinDivert) - запрашиваю...")
		}
		if err := relaunchAsAdmin(os.Args[1:]); err != nil {
			msg := "Нужны права администратора. Запусти dpi-bypass.exe правой кнопкой -> «Запуск от имени администратора»."
			if guiMode {
				messageBox(msg, false)
			} else {
				bad("%s", msg)
				pause()
			}
			os.Exit(1)
		}
		return
	}

	// окно уже открыто - показываем его, а не запускаем вторую копию
	if guiMode && cmd != "uitest" && activateExisting(cmd) {
		return
	}
	os.MkdirAll(dataDir, 0755)
	initLog(filepath.Join(dataDir, "log.txt"))
	initJob()
	loadSettings()

	if guiMode {
		runGUI(cmd)
		return
	}

	banner()
	if isARM64() {
		warn("Это Windows на ARM-процессоре. Драйвер WinDivert для ARM64 официально не подписан,")
		say("      поэтому обход DPI здесь, скорее всего, не запустится. Прокси для Telegram работать будет.")
	}
	go handleSignals()

	switch cmd {
	case "console":
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
	case "scan", "deep":
		target := ""
		if len(os.Args) > 2 {
			target = os.Args[2]
		}
		guard(func() { deepScanStandalone(target) })
		pause()
	case "tune":
		guard(func() { tuneStandalone() })
		pause()
	case "update":
		checkAndUpdate(true)
		pause()
	case "selftest":
		os.Exit(selftest())
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

// menu - консольное меню (dpi-bypass.exe console)
func menu() {
	go func() {
		if v, ok := latestVersion(); ok && newerVersion(v, version) {
			warn("Вышла новая версия %s (у тебя %s) - пункт 8.", v, version)
		}
	}()
	for {
		st := detectVPN()
		say("")
		switch {
		case len(otherInstances()) > 0:
			say("  Обход сейчас: %s", col(cGreen, "включён (в другом окне)"))
		case runningProcesses()["winws.exe"]:
			say("  Обход сейчас: %s", col(cYellow, "работает winws без программы"))
		default:
			say("  Обход сейчас: %s", col(cGray, "выключен"))
		}
		if st.Active() {
			say("  VPN:          %s", col(cYellow, vpnTitle(st)))
		} else {
			say("  VPN:          не найден")
		}
		say("")
		say("  %s  Включить обход (VPN будет выключен)", col(cBold+cCyan, "1"))
		say("  %s  Включить обход вместе с VPN", col(cBold+cCyan, "2"))
		say("  %s  Выключить обход и завершить всё", col(cBold+cCyan, "3"))
		say("  %s  Диагностика (сайты, VPN, сеть)", col(cBold+cCyan, "4"))
		say("  %s  Подобрать стратегии заново", col(cBold+cCyan, "5"))
		say("  %s  Защитник Windows: исключения и карантин", col(cBold+cCyan, "6"))
		say("  %s  Глубокая проверка сайта (долго)", col(cBold+cCyan, "7"))
		say("  %s  Проверить обновление программы", col(cBold+cCyan, "8"))
		say("  %s  Выход", col(cBold+cCyan, "0"))
		fmt.Fprint(out, "\n  Выбери [1-8, 0]: ")
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
			guard(diagnostics)
		case "5":
			startBypass(modeWithVPN, true)
			return
		case "6":
			defenderHelp()
		case "7":
			fmt.Fprint(out, "  Сайт (например rutracker.org), Enter - все неоткрывающиеся: ")
			t := readLine()
			guard(func() { deepScanStandalone(t) })
		case "8":
			checkAndUpdate(true)
		case "0", "q":
			return
		default:
			warn("Нужно ввести цифру от 0 до 8")
		}
	}
}

func vpnTitle(v VPNState) string {
	return firstNonEmpty(strings.Join(v.Procs, ", "), strings.Join(v.TunNames, ", ")) + " (" + v.Mode() + ")"
}

var stdin = bufio.NewReader(os.Stdin)

func readLine() string {
	l, _ := stdin.ReadString('\n')
	return strings.TrimSpace(l)
}

func askYes(q string) bool {
	if guiMode {
		return messageBox(q, true)
	}
	fmt.Fprintf(out, "%s %s ", col(cYellow, "[?]"), q+" [Enter - да / n - нет]:")
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
	stopEngine()
	stopOthers()
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
	showISP()
	diagnose(svcs)
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
	stopEngine()
	stopActive()
	good("Остановлено. Интернет работает как обычно.")
	os.Exit(0)
}

var updatesDone bool

func mustPrepare() []Service {
	if err := ensureZapret(); err != nil {
		say("\nМожно скачать вручную: github.com/bol-van/zapret-win-bundle -> папку zapret-winws")
		say("положи рядом с dpi-bypass.exe. Если файлы удаляет антивирус - «Защитник» в меню.")
		fail("%v", err)
	}
	if !updatesDone {
		loadServices() // создаёт sites.txt, если его нет
		applyUpdates()
		updatesDone = true
	}
	svcs, err := loadServices()
	if err != nil || len(svcs) == 0 {
		fail("Не удалось прочитать %s: %v", sitesPath(), err)
	}
	return svcs
}
