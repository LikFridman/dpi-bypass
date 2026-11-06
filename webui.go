//go:build windows

package main

// Окно «Ночь»: страница ui/index.html в WebView2 (движок Edge, есть в Windows 10/11).
// На Windows 11 под страницей - настоящее размытое стекло (Acrylic). Если WebView2 нет -
// откроется простое окно из gui.go.

import (
	"dpibypass/tg"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
)

//go:embed ui/index.html
var uiHTML string

const webTitle = "dpi-bypass"

type uiSiteRow struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"` // ok | custom | vpn | bad | idle
	Label    string `json:"label"`
	Strategy string `json:"strategy"`
	Detail   string `json:"detail,omitempty"`
}

type uiProgress struct {
	Cur   int    `json:"cur"`
	Total int    `json:"total"`
	Label string `json:"label"`
}

type uiState struct {
	Version     string      `json:"version"`
	Running     bool        `json:"running"`
	Starting    bool        `json:"starting"`
	Busy        bool        `json:"busy"`
	Mode        int         `json:"mode"`
	Status      string      `json:"status"`
	ISP         string      `json:"isp"`
	VPN         string      `json:"vpn"`
	Sites       []uiSiteRow `json:"sites"`
	SitesOK     int         `json:"sitesOk"`
	SitesTotal  int         `json:"sitesTotal"`
	Checked     string      `json:"checked"`
	TgLink      string      `json:"tgLink"`
	TgStats     string      `json:"tgStats"`
	TgProxies   []string    `json:"tgProxies"`
	TgFound     []tg.Found  `json:"tgFound"`
	TgFoundAt   string      `json:"tgFoundAt"`
	TgSearch    bool        `json:"tgSearching"`
	Pinging     bool        `json:"pinging"`
	NeedConsent bool        `json:"needConsent"`
	Agreement   string      `json:"agreement,omitempty"`
	Autostart   bool        `json:"autostart"`
	Tray        bool        `json:"tray"`
	Update      string      `json:"update"`
	Dir         string      `json:"dir"`
	Missing     []string    `json:"missing"`
	Progress    uiProgress  `json:"progress"`
	DeepActive  bool        `json:"deepActive"`
}

type uiPush struct {
	State  *uiState         `json:"state,omitempty"`
	Logs   []string         `json:"logs,omitempty"`
	Events []map[string]any `json:"events,omitempty"`
}

var (
	wv          webview2.WebView
	webUIActive bool

	uiMu        sync.Mutex
	uiLogs      []string // ещё не отправленные строки
	uiHistory   []string // последние строки - для страницы после загрузки
	uiPartial   string
	uiEvents    []map[string]any
	uiLastJSON  string
	uiPageReady atomic.Bool // страница загрузилась - можно слать обновления

	engineGoroutine atomic.Bool
	deepActive      atomic.Bool
	progCur         atomic.Int64
	progTotal       atomic.Int64
	autostartCache  atomic.Bool
	// режим, который хотели включить до принятия соглашения
	consentPendingMode atomic.Int32
	infoISP            atomic.Value // string
	infoVPN            atomic.Value // string

	confirmMu   sync.Mutex
	confirmSeq  int
	confirmWait = map[int]chan bool{}

	webOrigProc uintptr
	uitestMode  bool
)

// ---------- вывод программы в окно ----------

type webLogWriter struct{}

func (webLogWriter) Write(p []byte) (int, error) {
	s := ansiRe.ReplaceAllString(string(p), "")
	uiMu.Lock()
	s = uiPartial + strings.ReplaceAll(s, "\r", "")
	parts := strings.Split(s, "\n")
	uiPartial = parts[len(parts)-1]
	for _, l := range parts[:len(parts)-1] {
		uiLogs = append(uiLogs, l)
		uiHistory = append(uiHistory, l)
	}
	if len(uiHistory) > 1500 {
		uiHistory = append([]string{}, uiHistory[len(uiHistory)-1500:]...)
	}
	uiMu.Unlock()
	return len(p), nil
}

func uiEvent(e map[string]any) {
	uiMu.Lock()
	uiEvents = append(uiEvents, e)
	uiMu.Unlock()
}

func uiToast(text string) { uiEvent(map[string]any{"t": "toast", "text": text}) }

// uiConfirm показывает стеклянное окно «Да/Нет» и ждёт ответа (вызывать не из потока окна)
func uiConfirm(text string) bool {
	confirmMu.Lock()
	confirmSeq++
	id := confirmSeq
	ch := make(chan bool, 1)
	confirmWait[id] = ch
	confirmMu.Unlock()
	if w := guiHwnd; w != 0 {
		showMainWindow()
	}
	uiEvent(map[string]any{"t": "confirm", "id": id, "text": text})
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Minute):
		return false
	}
}

// ---------- состояние для страницы ----------

var (
	engCfgMu  sync.Mutex
	engCfg    *Config
	engRes    map[string]SvcResult
	engResAt  time.Time
	svcsCache []Service
	svcsAt    time.Time
)

// publishCfg - копия настроек работающего обхода для окна (без гонок с движком)
func publishCfg(c *Config) {
	if c == nil {
		return
	}
	cp := *c
	cp.Sites = map[string]string{}
	for k, v := range c.Sites {
		cp.Sites[k] = v
	}
	cp.Unfixable = map[string]string{}
	for k, v := range c.Unfixable {
		cp.Unfixable[k] = v
	}
	cp.Groups = append([]Group{}, c.Groups...)
	cp.Expected = append([]string{}, c.Expected...)
	engCfgMu.Lock()
	engCfg = &cp
	engCfgMu.Unlock()
}

func publishResults(res map[string]SvcResult) {
	cp := map[string]SvcResult{}
	for k, v := range res {
		cp[k] = v
	}
	engCfgMu.Lock()
	engRes, engResAt = cp, time.Now()
	engCfgMu.Unlock()
}

func clearResults() {
	engCfgMu.Lock()
	engRes = nil
	engCfgMu.Unlock()
}

func cachedServices() []Service {
	if time.Since(svcsAt) > 10*time.Second || svcsCache == nil {
		if s, err := loadServices(); err == nil {
			svcsCache, svcsAt = s, time.Now()
		}
	}
	return svcsCache
}

func ago(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < 20*time.Second:
		return "just now"
	case d < 90*time.Second:
		return "1 min ago"
	default:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	}
}

func siteRows() ([]uiSiteRow, int, int, string) {
	engCfgMu.Lock()
	cfg, res, at := engCfg, engRes, engResAt
	engCfgMu.Unlock()
	if cfg == nil {
		cfg = loadConfigCached()
	}
	running := engRunning.Load()
	pres, pat := lastPing()
	usePing := pres != nil && (!running || pat.After(at))
	var rows []uiSiteRow
	ok, total := 0, 0
	strat := map[string]string{}
	if cfg != nil {
		for _, g := range cfg.Groups {
			for _, n := range g.Services {
				strat[n] = g.Strategy + " · shared"
			}
		}
	}
	for _, s := range cachedServices() {
		row := uiSiteRow{Name: s.Name, Strategy: strat[s.Name]}
		custom := false
		if cfg != nil {
			for d := range cfg.Sites {
				if domainCovered(d, s.Domains) || domainCovered(s.Probes[0], []string{d}) {
					row.Strategy, custom = "custom · "+cfg.Sites[d], true
				}
			}
		}
		unfix := ""
		if cfg != nil {
			unfix = cfg.Unfixable[s.Name]
		}
		if pr, has := pres[s.Name]; usePing && has {
			total++
			if pr.OK {
				ok++
				row.Kind, row.Label = "ok", fmt.Sprintf("%d ms", pr.Ping)
				if pr.KBps > 0 {
					row.Detail = kbText(pr.KBps) + " · " + pr.What
				} else {
					row.Detail = pr.What
				}
			} else {
				row.Kind, row.Label, row.Detail = "bad", "none", pr.Stage+": "+pr.Reason
			}
			if row.Strategy == "" {
				row.Strategy = "direct"
			}
			if cfg != nil && cfg.Pins[s.Name] != "" {
				row.Strategy += " 📌"
			}
			rows = append(rows, row)
			continue
		}
		switch {
		case unfix != "" && s.Name == "Telegram" && running && (len(vpnSocks()) > 0 || curVPN.FullTunnel):
			row.Kind, row.Label, row.Strategy = "vpn", "via VPN", "IP blocked"
		case unfix != "" && (strings.Contains(unfix, "TCP") || strings.Contains(unfix, "DNS")):
			row.Kind, row.Label, row.Strategy = "bad", "none", "IP blocked · needs VPN"
		case unfix != "":
			row.Kind, row.Label = "bad", "none"
			if row.Strategy == "" {
				row.Strategy = "try deep scan"
			}
		case running && res != nil:
			total++
			if r, has := res[s.Name]; has && r.OK {
				ok++
				row.Kind, row.Label = "ok", pingLabel(r)
				if custom {
					row.Kind = "custom"
				}
			} else if has {
				row.Kind, row.Label, row.Detail = "bad", "none", stageNames[r.Stage]+": "+r.Reason
			} else {
				row.Kind, row.Label = "idle", "checking…"
			}
		case running:
			row.Kind, row.Label = "idle", "checking…"
		default:
			row.Kind, row.Label = "idle", "off"
		}
		if row.Strategy == "" {
			row.Strategy = "direct"
		}
		rows = append(rows, row)
	}
	// свои сайты не из списка (автосписок, глубокая проверка)
	if cfg != nil {
		var extra []string
		for d := range cfg.Sites {
			covered := false
			for _, s := range cachedServices() {
				if domainCovered(d, s.Domains) {
					covered = true
				}
			}
			if !covered {
				extra = append(extra, d)
			}
		}
		sortStrings(extra)
		for _, d := range extra {
			k, l := "idle", "off"
			if running {
				k, l = "custom", "custom"
			}
			rows = append(rows, uiSiteRow{Name: d, Kind: k, Label: l, Strategy: "custom · " + cfg.Sites[d]})
		}
	}
	checked := ""
	if running {
		checked = ago(at)
	}
	return rows, ok, total, checked
}

var (
	cfgCache   *Config
	cfgCacheAt time.Time
)

func loadConfigCached() *Config {
	if time.Since(cfgCacheAt) > 5*time.Second {
		cfgCache, cfgCacheAt = loadConfig(), time.Now()
	}
	return cfgCache
}

func buildUIState() uiState {
	st := uiState{
		Version: version, Running: engRunning.Load(), Busy: busy.Load(),
		Mode: settings.LastMode, Autostart: autostartCache.Load(), Tray: settings.Tray,
		Dir: baseDir, Missing: missingZapretFiles(), TgLink: tgCurrentLink, TgStats: tgStatusLine(),
		TgProxies:   tgUpstreamNames(),
		NeedConsent: !consentOK(),
		DeepActive:  deepActive.Load(),
	}
	st.Starting = engineGoroutine.Load() && !st.Running
	if engRunning.Load() {
		st.Mode = runMode
	}
	if s, ok := statusText.Load().(string); ok {
		st.Status = s
	}
	found, at := tgFoundList()
	st.TgFound, st.TgSearch = found, tgSearching.Load()
	if !at.IsZero() {
		st.TgFoundAt = ago(at)
	}
	if v, ok := infoISP.Load().(string); ok {
		st.ISP = v
	}
	if v, ok := infoVPN.Load().(string); ok {
		st.VPN = v
	}
	if v, ok := updateTo.Load().(string); ok {
		st.Update = v
	}
	st.Sites, st.SitesOK, st.SitesTotal, st.Checked = siteRows()
	st.Pinging = pinging.Load()
	if t := progTotal.Load(); t > 0 {
		st.Progress = uiProgress{Cur: int(progCur.Load()), Total: int(t), Label: st.Status}
	}
	if demoMode {
		st = demoState(st)
	}
	return st
}

// pushLoop отправляет в страницу состояние, новые строки журнала и события
func pushLoop() {
	for range time.Tick(300 * time.Millisecond) {
		if !uiPageReady.Load() {
			continue
		}
		st := buildUIState()
		b, _ := json.Marshal(st)
		uiMu.Lock()
		logs, evs := uiLogs, uiEvents
		uiLogs, uiEvents = nil, nil
		changed := string(b) != uiLastJSON
		if changed {
			uiLastJSON = string(b)
		}
		uiMu.Unlock()
		if !changed && len(logs) == 0 && len(evs) == 0 {
			continue
		}
		p := uiPush{Logs: logs, Events: evs}
		if changed {
			p.State = &st
		}
		js, _ := json.Marshal(p)
		wv.Dispatch(func() { wv.Eval("window.__push && window.__push(" + string(js) + ")") })
	}
}

// infoLoop раз в 30 секунд обновляет строки «провайдер» и «VPN»
func infoLoop() {
	for {
		v := detectVPN()
		vs := "VPN: не найден"
		if v.Active() {
			vs = "VPN: " + vpnTitle(v)
		}
		infoVPN.Store(vs)
		infoISP.Store(ispTitle(currentISP()))
		autostartCache.Store(autostartEnabled())
		time.Sleep(30 * time.Second)
	}
}

// ---------- команды из страницы ----------

func webStartEngine(mode int, reselect bool) {
	if !consentOK() {
		consentPendingMode.Store(int32(mode))
		uiEvent(map[string]any{"t": "consent"})
		if guiHwnd != 0 && wv != nil {
			wv.Dispatch(showMainWindow)
		}
		return
	}
	if engineGoroutine.Load() && !engRunning.Load() {
		uiToast("Обход уже запускается - подожди немного.")
		return
	}
	go func() {
		engineGoroutine.Store(true)
		defer func() {
			engineGoroutine.Store(false)
			clearResults()
		}()
		guard(func() { startBypass(mode, reselect) })
	}()
}

func webOp(fn func()) {
	if !busy.CompareAndSwap(false, true) {
		uiToast("Подожди - выполняется другое действие. Его можно прервать кнопкой «Стоп».")
		return
	}
	go func() {
		defer func() {
			cancelFlag.Store(false)
			busy.Store(false)
		}()
		guard(fn)
	}()
}

func openFile(p string) {
	c := exec.Command("notepad.exe", p)
	c.Start()
}

func webCall(cmd, arg string) (any, error) {
	switch cmd {
	case "ready", "poll", "logs", "state", "bgGet", "bgSet":
	default:
		a := arg
		if len(a) > 80 {
			a = a[:80]
		}
		recordAction(strings.TrimSpace(cmd + " " + a))
	}
	switch cmd {
	case "ready":
		select {
		case uitestReady <- struct{}{}:
		default:
		}
		st := buildUIState()
		b, _ := json.Marshal(st)
		uiMu.Lock()
		hist := append([]string{}, uiHistory...)
		uiLogs = nil
		uiLastJSON = string(b)
		uiMu.Unlock()
		uiPageReady.Store(true)
		return uiPush{State: &st, Logs: hist}, nil
	case "on":
		m, _ := strconv.Atoi(arg)
		if m != modeNoVPN {
			m = modeWithVPN
		}
		webStartEngine(m, false)
	case "off":
		go shutdownAll()
	case "reselect":
		webStartEngine(settings.LastMode, true)
	case "diag":
		uiEvent(map[string]any{"t": "go", "p": "log"})
		webOp(diagnostics)
	case "tune":
		if !requestTune() {
			uiEvent(map[string]any{"t": "go", "p": "log"})
			webOp(tuneStandalone)
		} else {
			uiToast("Подбираю стратегии для новых сайтов - обход прервётся на минуту.")
		}
	case "deep":
		target := arg
		webOp(func() {
			deepActive.Store(true)
			defer func() {
				deepActive.Store(false)
				progTotal.Store(0)
			}()
			wasRunning, mode := engRunning.Load(), runMode
			if wasRunning {
				info("Глубокой проверке нужен winws - временно выключаю обход.")
				stopEngine()
			}
			defer func() {
				if wasRunning {
					webStartEngine(mode, false)
				}
			}()
			deepScanStandalone(target)
		})
	case "stop":
		if busy.Load() || engineGoroutine.Load() {
			cancelFlag.Store(true)
			uiToast("Останавливаю...")
		}
	case "update":
		webOp(func() { checkAndUpdate(true) })
	case "share":
		if cfg := loadConfig(); cfg == nil {
			uiToast("Пока нечем делиться - сначала включи обход, чтобы подобрались стратегии.")
		} else {
			openURL(shareURL(cfg))
		}
	case "tgOpen":
		if tgCurrentLink == "" {
			uiToast("Прокси для Telegram запускается вместе с обходом - сначала включи обход.")
		} else {
			openURL(tgCurrentLink)
		}
	case "tgAddProxy":
		u, err := tgAddUpstream(arg)
		if err != nil {
			uiToast("Ссылка не подходит: " + err.Error())
		} else {
			uiToast("Добавлен запасной прокси: " + u.String())
			info("Telegram: добавлен запасной прокси %s", u)
		}
	case "consent":
		if arg == "1" {
			setConsent(true)
			info("Пользовательское соглашение принято.")
			if m := consentPendingMode.Swap(0); m != 0 {
				webStartEngine(int(m), false)
			}
		} else {
			setConsent(false)
			go func() {
				time.Sleep(300 * time.Millisecond)
				shutdownAll()
				os.Exit(0)
			}()
		}
	case "agreement":
		return agreementText, nil
	case "report":
		go sendReport("manual")
		uiToast("Собираю отчёт...")
	case "pingAll":
		pingAllAsync()
	case "siteStrategies":
		return siteStrategiesJSON(arg), nil
	case "testStrategy":
		p := strings.SplitN(arg, "|", 2)
		if len(p) == 2 {
			testOneStrategy(p[0], p[1])
		}
	case "pin":
		p := strings.SplitN(arg, "|", 2)
		if len(p) == 2 {
			go pinStrategy(p[0], p[1])
		}
	case "tgFind":
		tgDiscoverAsync(true)
	case "tgUse":
		if u, err := tgAddUpstream(arg); err != nil {
			uiToast("Ссылка не подходит: " + err.Error())
		} else {
			uiToast("Добавлен в запасные: " + u.String())
		}
	case "tgOpenLink":
		if strings.HasPrefix(arg, "tg://proxy?") {
			openURL(arg)
		}
	case "tgClearProxies":
		os.Remove(tgProxiesFile())
		uiToast("Запасные прокси удалены")
	case "openWorker":
		if !fileExists(tgWorkerJS()) {
			os.WriteFile(tgWorkerJS(), []byte(workerJS), 0644)
		}
		openFile(tgWorkerJS())
	case "openSites":
		openFile(sitesPath())
	case "openLog":
		openFile(logPath)
	case "openDir":
		exec.Command("explorer.exe", baseDir).Start()
	case "copyPath":
		if copyToClipboard(baseDir) {
			uiToast("Путь скопирован: " + baseDir)
		}
	case "defSettings":
		openURL("windowsdefender://threatsettings")
	case "defHistory":
		openURL("windowsdefender://threat")
	case "autostart":
		on := arg == "1"
		go func() {
			if err := setAutostart(on); err != nil {
				bad("Автозапуск: %v", err)
				uiToast("Не удалось изменить автозапуск: " + err.Error())
			} else if on {
				uiToast("Автозапуск включён: обход включится сам при входе в Windows.")
			} else {
				uiToast("Автозапуск выключен.")
			}
			autostartCache.Store(autostartEnabled())
		}()
	case "tray":
		settings.Tray = arg == "1"
		saveSettings()
	case "bgGet":
		return bgInfo(), nil
	case "bgSet":
		if err := saveBackground(arg); err != nil {
			uiToast("Не получилось поставить фон: " + err.Error())
			return nil, nil
		}
		uiToast("Фон обновлён")
		return bgInfo(), nil
	case "bgClear":
		if settings.BgFile != "" {
			os.Remove(filepath.Join(dataDir, settings.BgFile))
		}
		settings.BgFile = ""
		saveSettings()
		return bgInfo(), nil
	case "bgOpts":
		var d, b int
		fmt.Sscanf(arg, "%d:%d", &d, &b)
		settings.BgDim, settings.BgBlur = clampInt(d, 0, 90), clampInt(b, 0, 30)
		saveSettings()
	case "reset":
		go func() {
			if !uiConfirm("Сбросить настройки?\nОбход выключится, стратегии подберутся заново при следующем включении.") {
				return
			}
			stopEngine()
			os.Remove(cfgPath())
			os.Remove(autoListFile())
			cfgCacheAt = time.Time{}
			good("Настройки сброшены.")
			uiToast("Настройки сброшены.")
		}()
	case "answer":
		p := strings.SplitN(arg, ":", 2)
		if len(p) == 2 {
			id, _ := strconv.Atoi(p[0])
			confirmMu.Lock()
			ch := confirmWait[id]
			delete(confirmWait, id)
			confirmMu.Unlock()
			if ch != nil {
				ch <- p[1] == "1"
			}
		}
	case "jsError":
		fmt.Fprintf(logFileWriter, "[js] %s\n", arg)
		if uitestMode {
			uitestErrs = append(uitestErrs, "js: "+arg)
		}
	case "uitest":
		uitestReport <- arg
	}
	return nil, nil
}

// ---------- окно, стекло, трей ----------

var (
	dwmapi                    = syscall.NewLazyDLL("dwmapi.dll")
	pDwmSetWindowAttribute    = dwmapi.NewProc("DwmSetWindowAttribute")
	pDwmExtendFrameIntoClient = dwmapi.NewProc("DwmExtendFrameIntoClientArea")
	pRtlGetVersion            = syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion")
	pSetWindowLongPtrW        = syscall.NewLazyDLL("user32.dll").NewProc("SetWindowLongPtrW")
	pCallWindowProcW          = syscall.NewLazyDLL("user32.dll").NewProc("CallWindowProcW")
	pSendMessageW2            = syscall.NewLazyDLL("user32.dll").NewProc("SendMessageW")
)

func windowsBuild() uint32 {
	var v struct {
		Size, Major, Minor, Build, Platform uint32
		CSD                                 [128]uint16
	}
	v.Size = uint32(unsafe.Sizeof(v))
	pRtlGetVersion.Call(uintptr(unsafe.Pointer(&v)))
	return v.Build
}

var (
	pGetDpiForSystem = syscall.NewLazyDLL("user32.dll").NewProc("GetDpiForSystem")
	pSetWindowPos    = syscall.NewLazyDLL("user32.dll").NewProc("SetWindowPos")
	pRtlMoveMemory   = syscall.NewLazyDLL("kernel32.dll").NewProc("RtlMoveMemory")
)

// systemDPI - масштаб экрана (96 = 100%, 144 = 150%)
func systemDPI() uint32 {
	if pGetDpiForSystem.Find() != nil {
		return 96
	}
	d, _, _ := pGetDpiForSystem.Call()
	if d < 96 || d > 480 {
		return 96
	}
	return uint32(d)
}

func dwmAttr(hwnd uintptr, attr uint32, val uint32) bool {
	r, _, _ := pDwmSetWindowAttribute.Call(hwnd, uintptr(attr), uintptr(unsafe.Pointer(&val)), 4)
	return r == 0
}

// setupGlass: тёмный заголовок в цвет фона страницы. Системное стекло Acrylic больше не
// включается: оно делало окно мыльным, давало серую полосу заголовка и нагружало видеокарту.
func setupGlass(hwnd uintptr) bool {
	dwmAttr(hwnd, 19, 1) // тёмный заголовок (старые сборки Windows 10)
	dwmAttr(hwnd, 20, 1) // DWMWA_USE_IMMERSIVE_DARK_MODE
	if windowsBuild() >= 22000 {
		dwmAttr(hwnd, 35, 0x001C0A07) // DWMWA_CAPTION_COLOR = #070a1c (COLORREF 0x00BBGGRR)
		dwmAttr(hwnd, 34, 0x00301A12) // DWMWA_BORDER_COLOR - тёмная рамка
		dwmAttr(hwnd, 36, 0x00FBF0EE) // DWMWA_TEXT_COLOR = #eef0fb
	}
	return false
}

func webWndProc(hwnd, msg, wp, lp uintptr) uintptr {
	switch uint32(msg) {
	case wmClose:
		if settings.Tray && trayAdded && !quitting.Load() {
			hideToTray()
			return 0
		}
		go func() {
			if !engRunning.Load() || uiConfirm("Обход выключится. Закрыть программу?") {
				webQuit()
			}
		}()
		return 0
	case wmSize:
		if wp == 1 && settings.Tray && trayAdded { // свернули - в трей
			hideToTray()
			return 0
		}
	case 0x02E0: // WM_DPICHANGED: окно перенесли на экран с другим масштабом - берём размер, который предлагает Windows
		var r [4]int32
		pRtlMoveMemory.Call(uintptr(unsafe.Pointer(&r[0])), lp, 16)
		pSetWindowPos.Call(hwnd, 0, uintptr(r[0]), uintptr(r[1]), uintptr(r[2]-r[0]), uintptr(r[3]-r[1]), 0x0014) // SWP_NOZORDER|SWP_NOACTIVATE
		return 0
	case wmAppTray:
		switch uint32(lp & 0xFFFF) {
		case wmLButtonUp, wmLButtonDblClk:
			showMainWindow()
		case wmRButtonUp:
			trayMenu()
		}
		return 0
	}
	if msgTaskbarCreated != 0 && msg == msgTaskbarCreated {
		addTrayIcon()
		return 0
	}
	r, _, _ := pCallWindowProcW.Call(webOrigProc, hwnd, msg, wp, lp)
	return r
}

func webTrayCommand(id int) {
	switch id {
	case idOpen:
		showMainWindow()
	case idOn:
		webStartEngine(modeNoVPN, false)
	case idVPN:
		webStartEngine(modeWithVPN, false)
	case idOff:
		go shutdownAll()
	case idExit:
		webQuit()
	}
}

func webQuit() {
	if quitting.Swap(true) {
		return
	}
	pShowWindow.Call(guiHwnd, 0)
	go func() {
		stopEngine()
		stopActive()
		wv.Dispatch(func() {
			removeTrayIcon()
			wv.Terminate()
		})
	}()
}

// runWebUI запускает окно; false - WebView2 недоступен (тогда - простое окно)
func runWebUI(cmd string) bool {
	runtime.LockOSThread()
	uitestMode = cmd == "uitest"
	build := windowsBuild()
	glass := false // системное стекло выключено: с ним текст и карточки были мыльными
	// программа объявлена в манифесте как поддерживающая масштаб экрана (PerMonitorV2), поэтому
	// Windows не растягивает окно картинкой - размеры окна задаём с учётом масштаба
	scale := func(v int) int { return v * int(systemDPI()) / 96 }
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		DataPath:  filepath.Join(dataDir, "webview"),
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title: webTitle, Width: uint(scale(1180)), Height: uint(scale(760)), Center: true,
		},
	})
	if w == nil {
		return false
	}
	wv = w
	webUIActive = true
	hwnd := uintptr(w.Window())
	guiHwnd = hwnd
	hInst, _, _ = pGetModuleHandleW.Call(0)
	exe, _ := os.Executable()
	appIcon, _, _ = pExtractIconW.Call(hInst, uintptr(unsafe.Pointer(u16(exe))), 0)
	if appIcon > 1 {
		pSendMessageW2.Call(hwnd, 0x80, 1, appIcon) // WM_SETICON big
		pSendMessageW2.Call(hwnd, 0x80, 0, appIcon) // small
	} else {
		appIcon, _, _ = pLoadIconW.Call(0, 32512)
	}
	native := false
	if glass {
		native = setupGlass(hwnd)
	} else {
		setupGlass(hwnd) // хотя бы тёмный заголовок
	}
	w.SetSize(scale(980), scale(640), webview2.HintMin)
	webOrigProc, _, _ = pSetWindowLongPtrW.Call(hwnd, uintptr(^uintptr(3)), syscall.NewCallback(webWndProc)) // GWLP_WNDPROC = -4
	msgTaskbarCreated, _, _ = pRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(u16("TaskbarCreated"))))
	trayCommand = webTrayCommand

	out = ioMulti(webLogWriter{}, logFileWriter)
	statusHook = func(string) {}
	w.Bind("dpiCall", webCall)
	w.Init(fmt.Sprintf("window.__native={glass:%v,build:%d,test:%v};", native, build, uitestMode))
	w.SetHtml(uiHTML)

	if !uitestMode {
		addTrayIcon()
	}
	if cmd == "autostart" && settings.Tray && trayAdded {
		pShowWindow.Call(hwnd, 0)
	}

	banner()
	if isARM64() {
		warn("Это Windows на ARM-процессоре. Драйвер WinDivert для ARM64 официально не подписан,")
		say("      поэтому обход DPI здесь, скорее всего, не запустится. Прокси для Telegram работать будет.")
	}
	info("Журнал работы сохраняется в %s", logPath)
	go pushLoop()
	if !uitestMode {
		go infoLoop()
		go func() {
			if v, ok := latestVersion(); ok && newerVersion(v, version) {
				updateTo.Store(v)
				warn("Вышла новая версия %s - кнопка «Обновить» слева внизу.", v)
			}
		}()
	}

	switch {
	case uitestMode:
		go runUITest()
	case cmd == "autostart":
		info("Автозапуск: включаю обход (%s).", modeName(settings.LastMode))
		webStartEngine(settings.LastMode, false)
	case strings.HasPrefix(cmd, "resume") && len(cmd) > 6:
		m := modeWithVPN
		if cmd == "resume1" {
			m = modeNoVPN
		}
		good("Программа обновлена до версии %s - включаю обход обратно.", version)
		webStartEngine(m, false)
	case cmd == "resume":
		good("Программа обновлена до версии %s.", version)
	}
	// отчёт при каждом запуске программы (если соглашение уже принято)
	go func() {
		time.Sleep(8 * time.Second)
		sendReport("launch")
	}()

	w.Run()
	stopActive()
	time.Sleep(200 * time.Millisecond)
	if uitestMode {
		os.Exit(uitestExit)
	}
	os.Exit(0)
	return true
}

// runGUI - окно «Ночь» на WebView2, а если его нет - простое окно
func runGUI(cmd string) {
	if runWebUI(cmd) {
		return
	}
	if cmd == "uitest" {
		os.WriteFile(filepath.Join(baseDir, "uitest.txt"), []byte("FAIL\nWebView2 не запустился\n"), 0644)
		os.Exit(1)
	}
	runClassicGUI(cmd)
}
