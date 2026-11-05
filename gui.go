//go:build windows

package main

// Окно с кнопками и значок в трее - на чистом WinAPI, без сторонних библиотек.

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	u32 = syscall.NewLazyDLL("user32.dll")
	g32 = syscall.NewLazyDLL("gdi32.dll")
	s32 = syscall.NewLazyDLL("shell32.dll")

	pRegisterClassExW       = u32.NewProc("RegisterClassExW")
	pCreateWindowExW        = u32.NewProc("CreateWindowExW")
	pDefWindowProcW         = u32.NewProc("DefWindowProcW")
	pShowWindow             = u32.NewProc("ShowWindow")
	pUpdateWindow           = u32.NewProc("UpdateWindow")
	pGetMessageW            = u32.NewProc("GetMessageW")
	pTranslateMessage       = u32.NewProc("TranslateMessage")
	pDispatchMessageW       = u32.NewProc("DispatchMessageW")
	pIsDialogMessageW       = u32.NewProc("IsDialogMessageW")
	pPostMessageW           = u32.NewProc("PostMessageW")
	pSendMessageW           = u32.NewProc("SendMessageW")
	pPostQuitMessage        = u32.NewProc("PostQuitMessage")
	pDestroyWindow          = u32.NewProc("DestroyWindow")
	pMoveWindow             = u32.NewProc("MoveWindow")
	pGetClientRect          = u32.NewProc("GetClientRect")
	pSetWindowTextW         = u32.NewProc("SetWindowTextW")
	pGetWindowTextW         = u32.NewProc("GetWindowTextW")
	pGetWindowTextLengthW   = u32.NewProc("GetWindowTextLengthW")
	pEnableWindow           = u32.NewProc("EnableWindow")
	pLoadCursorW            = u32.NewProc("LoadCursorW")
	pLoadIconW              = u32.NewProc("LoadIconW")
	pCreatePopupMenu        = u32.NewProc("CreatePopupMenu")
	pAppendMenuW            = u32.NewProc("AppendMenuW")
	pTrackPopupMenu         = u32.NewProc("TrackPopupMenu")
	pDestroyMenu            = u32.NewProc("DestroyMenu")
	pGetCursorPos           = u32.NewProc("GetCursorPos")
	pSetForegroundWindow    = u32.NewProc("SetForegroundWindow")
	pIsWindowVisible        = u32.NewProc("IsWindowVisible")
	pFindWindowW            = u32.NewProc("FindWindowW")
	pSetTimer               = u32.NewProc("SetTimer")
	pRegisterWindowMessageW = u32.NewProc("RegisterWindowMessageW")
	pCreateFontW            = g32.NewProc("CreateFontW")
	pGetStockObject         = g32.NewProc("GetStockObject")
	pSetBkColor             = g32.NewProc("SetBkColor")
	pShellNotifyIconW       = s32.NewProc("Shell_NotifyIconW")
	pExtractIconW           = s32.NewProc("ExtractIconW")
	pGetModuleHandleW       = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmCreate         = 0x0001
	wmDestroy        = 0x0002
	wmSize           = 0x0005
	wmClose          = 0x0010
	wmSetFont        = 0x0030
	wmCommand        = 0x0111
	wmTimer          = 0x0113
	wmCtlColorStatic = 0x0138
	wmGetMinMaxInfo  = 0x0024
	wmLButtonUp      = 0x0202
	wmLButtonDblClk  = 0x0203
	wmRButtonUp      = 0x0205
	wmAppLog         = 0x8001
	wmAppStatus      = 0x8002
	wmAppTray        = 0x8003
	wmAppBusy        = 0x8004
	wmAppQuit        = 0x8005
	wmAppInfo        = 0x8006
	wmAppEngine      = 0x8007

	wsOverlappedWindow = 0x00CF0000
	wsVisible          = 0x10000000
	wsChild            = 0x40000000
	wsTabStop          = 0x00010000
	wsVScroll          = 0x00200000
	wsClipChildren     = 0x02000000
	wsExClientEdge     = 0x00000200
	esMultiline        = 0x0004
	esAutoVScroll      = 0x0040
	esAutoHScroll      = 0x0080
	esReadOnly         = 0x0800
	bsPushButton       = 0x0000
	bsAutoCheckBox     = 0x0003
	ssEndEllipsis      = 0x4000
	ssNoPrefix         = 0x0080
	emSetSel           = 0x00B1
	emReplaceSel       = 0x00C2
	emSetLimitText     = 0x00C5
	emScrollCaret      = 0x00B7
	emSetCueBanner     = 0x1501
	bmGetCheck         = 0x00F0
	bmSetCheck         = 0x00F1
)

// идентификаторы кнопок и пунктов меню
const (
	idOn = 101 + iota
	idVPN
	idOff
	idDiag
	idReselect
	idTune
	idDefender
	idTG
	idDeep
	idStop
	idShare
	idUpdate
	idAuto
	idTray
	idSite
	idOpen
	idExit
)

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type winMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
	Private uint32
}

type rect struct{ Left, Top, Right, Bottom int32 }

type notifyIconData struct {
	Size            uint32
	Hwnd            uintptr
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            uintptr
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUIDItem        [16]byte
	BalloonIcon     uintptr
}

var (
	guiHwnd           uintptr
	hInst             uintptr
	appIcon           uintptr
	ctl               = map[int]uintptr{}
	hStatus           uintptr
	hInfo             uintptr
	hLog              uintptr
	fontUI            uintptr
	fontBold          uintptr
	fontMono          uintptr
	trayAdded         bool
	trayHint          bool
	msgTaskbarCreated uintptr

	logMu      sync.Mutex
	logPending strings.Builder
	statusMu   sync.Mutex
	statusNow  string
	infoNow    string
	busy       atomic.Bool
	updateTo   atomic.Value // string - доступная новая версия
	quitting   atomic.Bool
)

const className = "dpi-bypass-main"

// trayCommand - что делать с пунктом меню трея (своё для простого окна и для окна «Ночь»)
var trayCommand = func(id int) { onCommand(id) }

func u16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

func sendMsg(h uintptr, msg uint32, w, l uintptr) uintptr {
	r, _, _ := pSendMessageW.Call(h, uintptr(msg), w, l)
	return r
}

func postMsg(msg uint32, w, l uintptr) {
	if guiHwnd != 0 {
		pPostMessageW.Call(guiHwnd, uintptr(msg), w, l)
	}
}

func setText(h uintptr, s string) { pSetWindowTextW.Call(h, uintptr(unsafe.Pointer(u16(s)))) }

func getText(h uintptr) string {
	n, _, _ := pGetWindowTextLengthW.Call(h)
	buf := make([]uint16, n+1)
	pGetWindowTextW.Call(h, uintptr(unsafe.Pointer(&buf[0])), n+1)
	return syscall.UTF16ToString(buf)
}

func mkFont(size int32, bold bool, face string) uintptr {
	w := uintptr(400)
	if bold {
		w = 700
	}
	f, _, _ := pCreateFontW.Call(uintptr(uint32(-size)), 0, 0, 0, w, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(u16(face))))
	return f
}

func mkCtl(class, text string, style, exStyle uintptr, id int, font uintptr) uintptr {
	h, _, _ := pCreateWindowExW.Call(exStyle, uintptr(unsafe.Pointer(u16(class))), uintptr(unsafe.Pointer(u16(text))),
		wsChild|wsVisible|style, 0, 0, 10, 10, guiHwnd, uintptr(id), hInst, 0)
	sendMsg(h, wmSetFont, font, 1)
	if id != 0 {
		ctl[id] = h
	}
	return h
}

// ---------- вывод в окно ----------

type guiWriter struct{}

func (guiWriter) Write(p []byte) (int, error) {
	s := ansiRe.ReplaceAllString(string(p), "")
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
	logMu.Lock()
	logPending.WriteString(s)
	logMu.Unlock()
	postMsg(wmAppLog, 0, 0)
	return len(p), nil
}

func flushLog() {
	logMu.Lock()
	s := logPending.String()
	logPending.Reset()
	logMu.Unlock()
	if s == "" || hLog == 0 {
		return
	}
	if n, _, _ := pGetWindowTextLengthW.Call(hLog); n > 300000 {
		sendMsg(hLog, emSetSel, 0, 150000)
		sendMsg(hLog, emReplaceSel, 0, uintptr(unsafe.Pointer(u16(""))))
	}
	sendMsg(hLog, emSetSel, ^uintptr(0)>>1, ^uintptr(0)>>1)
	sendMsg(hLog, emReplaceSel, 0, uintptr(unsafe.Pointer(u16(s))))
	sendMsg(hLog, emScrollCaret, 0, 0)
}

// ---------- трей ----------

func trayData() *notifyIconData {
	d := &notifyIconData{Hwnd: guiHwnd, ID: 1, Flags: 0x1 | 0x2 | 0x4, CallbackMessage: wmAppTray, Icon: appIcon}
	d.Size = uint32(unsafe.Sizeof(*d))
	tip := "dpi-bypass"
	statusMu.Lock()
	if statusNow != "" {
		tip = "dpi-bypass: " + statusNow
	}
	statusMu.Unlock()
	t := syscall.StringToUTF16(tip)
	if len(t) > 127 {
		t = append(t[:126], 0)
	}
	copy(d.Tip[:], t)
	return d
}

func addTrayIcon() {
	d := trayData()
	r, _, _ := pShellNotifyIconW.Call(0, uintptr(unsafe.Pointer(d))) // NIM_ADD
	trayAdded = r != 0
}

func updateTrayIcon() {
	if trayAdded {
		pShellNotifyIconW.Call(1, uintptr(unsafe.Pointer(trayData()))) // NIM_MODIFY
	}
}

func trayBalloon(title, text string) {
	if !trayAdded {
		return
	}
	d := trayData()
	d.Flags |= 0x10 // NIF_INFO
	copy(d.Info[:], syscall.StringToUTF16(text))
	copy(d.InfoTitle[:], syscall.StringToUTF16(title))
	d.InfoFlags = 1 // NIIF_INFO
	pShellNotifyIconW.Call(1, uintptr(unsafe.Pointer(d)))
}

func removeTrayIcon() {
	if trayAdded && guiHwnd != 0 {
		pShellNotifyIconW.Call(2, uintptr(unsafe.Pointer(trayData()))) // NIM_DELETE
		trayAdded = false
	}
}

func showMainWindow() {
	pShowWindow.Call(guiHwnd, 9) // SW_RESTORE
	pShowWindow.Call(guiHwnd, 5)
	pSetForegroundWindow.Call(guiHwnd)
}

func hideToTray() {
	pShowWindow.Call(guiHwnd, 0)
	if !trayHint {
		trayHint = true
		trayBalloon("dpi-bypass работает в фоне", "Значок здесь. Нажми на него, чтобы открыть окно.")
	}
}

func trayMenu() {
	m, _, _ := pCreatePopupMenu.Call()
	add := func(id int, text string, enabled bool) {
		flags := uintptr(0)
		if !enabled {
			flags = 1
		}
		pAppendMenuW.Call(m, flags, uintptr(id), uintptr(unsafe.Pointer(u16(text))))
	}
	running := engRunning.Load()
	add(idOpen, "Открыть окно", true)
	pAppendMenuW.Call(m, 0x800, 0, 0)
	add(idOn, "Включить обход (без VPN)", true)
	add(idVPN, "Включить обход вместе с VPN", true)
	add(idOff, "Выключить обход", running)
	pAppendMenuW.Call(m, 0x800, 0, 0)
	add(idExit, "Выход", true)
	var pt struct{ X, Y int32 }
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForegroundWindow.Call(guiHwnd)
	cmd, _, _ := pTrackPopupMenu.Call(m, 0x100|0x2, uintptr(pt.X), uintptr(pt.Y), 0, guiHwnd, 0) // TPM_RETURNCMD|TPM_RIGHTBUTTON
	pDestroyMenu.Call(m)
	if cmd != 0 {
		trayCommand(int(cmd))
	}
}

// ---------- действия ----------

// runOp - разовое действие в фоне (диагностика, проверка и т.п.); одновременно - одно
func runOp(fn func()) {
	if !busy.CompareAndSwap(false, true) {
		messageBox("Подожди - выполняется другое действие. Его можно прервать кнопкой «Стоп».", false)
		return
	}
	postMsg(wmAppBusy, 1, 0)
	go func() {
		defer func() {
			cancelFlag.Store(false)
			busy.Store(false)
			postMsg(wmAppBusy, 0, 0)
		}()
		guard(fn)
	}()
}

func startEngineAsync(mode int, reselect bool) {
	postMsg(wmAppEngine, 1, 0)
	go func() {
		defer postMsg(wmAppEngine, 0, 0)
		guard(func() { startBypass(mode, reselect) })
		refreshInfoAsync()
	}()
}

func refreshInfoAsync() {
	go func() {
		v := detectVPN()
		vs := "VPN: не найден"
		if v.Active() {
			vs = "VPN: " + vpnTitle(v)
		}
		s := fmt.Sprintf("%s     Провайдер: %s     Версия: %s", vs, ispTitle(currentISP()), version)
		if nv, _ := updateTo.Load().(string); nv != "" {
			s += " (есть " + nv + ")"
		}
		statusMu.Lock()
		infoNow = s
		statusMu.Unlock()
		postMsg(wmAppInfo, 0, 0)
	}()
}

func onCommand(id int) {
	switch id {
	case idOn:
		startEngineAsync(modeNoVPN, false)
	case idVPN:
		startEngineAsync(modeWithVPN, false)
	case idOff:
		go func() {
			shutdownAll()
			refreshInfoAsync()
		}()
	case idDiag:
		runOp(diagnostics)
	case idReselect:
		startEngineAsync(settings.LastMode, true)
	case idTune:
		if !requestTune() {
			runOp(tuneStandalone)
		}
	case idDefender:
		runOp(defenderHelp)
	case idTG:
		if tgCurrentLink == "" {
			messageBox("Прокси для Telegram запускается вместе с обходом - сначала включи обход.", false)
		} else {
			openURL(tgCurrentLink)
			info("Открыл ссылку прокси для Telegram - в Telegram нажми «Подключиться».")
		}
	case idDeep:
		target := getText(ctl[idSite])
		runOp(func() {
			wasRunning, mode := engRunning.Load(), runMode
			if wasRunning {
				info("Глубокой проверке нужен winws - временно выключаю обход.")
				stopEngine()
			}
			defer func() {
				if wasRunning {
					startEngineAsync(mode, false)
				}
			}()
			deepScanStandalone(target)
		})
	case idStop:
		if busy.Load() || !engRunning.Load() {
			cancelFlag.Store(true)
			info("Останавливаю...")
		}
	case idShare:
		cfg := loadConfig()
		if cfg == nil {
			messageBox("Пока нечем делиться - сначала включи обход, чтобы подобрались стратегии.", false)
			return
		}
		if messageBox("Откроется страница GitHub с готовым текстом: провайдер и стратегии, которые сработали.\n"+
			"Никаких адресов и личных данных там нет. Отправить можно кнопкой на странице (нужен аккаунт GitHub).\n\nОткрыть?", true) {
			openURL(shareURL(cfg))
		}
	case idUpdate:
		runOp(func() { checkAndUpdate(true) })
	case idAuto:
		on := sendMsg(ctl[idAuto], bmGetCheck, 0, 0) == 1
		go func() {
			if err := setAutostart(on); err != nil {
				bad("Автозапуск: %v", err)
				messageBox("Не удалось изменить автозапуск: "+err.Error(), false)
			} else if on {
				good("Автозапуск включён: при входе в Windows обход включится сам (режим «%s»).", modeName(settings.LastMode))
			} else {
				good("Автозапуск выключен.")
			}
			check := uintptr(0)
			if autostartEnabled() {
				check = 1
			}
			sendMsg(ctl[idAuto], bmSetCheck, check, 0)
		}()
	case idTray:
		settings.Tray = sendMsg(ctl[idTray], bmGetCheck, 0, 0) == 1
		saveSettings()
	case idOpen:
		showMainWindow()
	case idExit:
		quitApp()
	}
}

func modeName(m int) string {
	if m == modeNoVPN {
		return "без VPN"
	}
	return "вместе с VPN"
}

func quitApp() {
	if quitting.Swap(true) {
		return
	}
	pShowWindow.Call(guiHwnd, 0)
	go func() {
		stopEngine()
		stopActive()
		postMsg(wmAppQuit, 0, 0)
	}()
}

func setBusyUI(b bool) {
	for _, id := range []int{idDiag, idReselect, idTune, idDefender, idDeep, idShare, idUpdate} {
		e := uintptr(1)
		if b {
			e = 0
		}
		pEnableWindow.Call(ctl[id], e)
	}
}

// ---------- раскладка ----------

func layout() {
	var r rect
	pGetClientRect.Call(guiHwnd, uintptr(unsafe.Pointer(&r)))
	w, h := r.Right, r.Bottom
	mv := func(hw uintptr, x, y, cw, ch int32) {
		pMoveWindow.Call(hw, uintptr(x), uintptr(y), uintptr(cw), uintptr(ch), 1)
	}
	const m = 12
	mv(hStatus, m, 10, w-2*m, 24)
	mv(hInfo, m, 36, w-2*m, 20)
	x := int32(m)
	row := func(y, hh int32, items ...struct {
		id int
		w  int32
	}) {
		x = m
		for _, it := range items {
			mv(ctl[it.id], x, y, it.w, hh)
			x += it.w + 8
		}
	}
	type it = struct {
		id int
		w  int32
	}
	row(64, 36, it{idOn, 230}, it{idVPN, 230}, it{idOff, 170})
	row(110, 30, it{idDiag, 120}, it{idReselect, 160}, it{idTune, 130}, it{idDefender, 110}, it{idTG, 110})
	row(150, 28, it{idSite, 230}, it{idDeep, 160}, it{idStop, 80}, it{idShare, 200})
	row(188, 24, it{idAuto, 260}, it{idTray, 200}, it{idUpdate, 170})
	mv(hLog, m, 222, w-2*m, h-222-m)
}

// ---------- окно ----------

func wndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch uint32(msg) {
	case wmCreate:
		guiHwnd = hwnd
		createControls()
		return 0
	case wmSize:
		if wparam == 1 && settings.Tray && trayAdded { // свернули - прячем в трей
			hideToTray()
			return 0
		}
		layout()
		return 0
	case wmGetMinMaxInfo:
		minSize := [2]int32{900, 480} // ptMinTrackSize
		procRtlMoveMemory.Call(lparam+24, uintptr(unsafe.Pointer(&minSize[0])), 8)
		return 0
	case wmCommand:
		id := int(wparam & 0xFFFF)
		if id == idSite {
			return 0
		}
		onCommand(id)
		return 0
	case wmCtlColorStatic:
		if lparam == hLog { // журнал - на белом фоне
			pSetBkColor.Call(wparam, 0xFFFFFF)
			b, _, _ := pGetStockObject.Call(0) // WHITE_BRUSH
			return b
		}
	case wmTimer:
		refreshInfoAsync()
		return 0
	case wmAppLog:
		flushLog()
		return 0
	case wmAppStatus:
		statusMu.Lock()
		s := statusNow
		statusMu.Unlock()
		setText(hStatus, s)
		updateTrayIcon()
		return 0
	case wmAppInfo:
		statusMu.Lock()
		s := infoNow
		statusMu.Unlock()
		setText(hInfo, s)
		if nv, _ := updateTo.Load().(string); nv != "" {
			setText(ctl[idUpdate], "Обновить до "+nv)
		}
		return 0
	case wmAppBusy:
		setBusyUI(wparam == 1)
		return 0
	case wmAppEngine:
		return 0
	case wmAppTray:
		switch uint32(lparam & 0xFFFF) {
		case wmLButtonUp, wmLButtonDblClk:
			showMainWindow()
		case wmRButtonUp:
			trayMenu()
		}
		return 0
	case wmAppQuit:
		pDestroyWindow.Call(hwnd)
		return 0
	case wmClose:
		if settings.Tray && engRunning.Load() && trayAdded && !quitting.Load() {
			hideToTray()
			return 0
		}
		if engRunning.Load() && !messageBox("Обход выключится. Закрыть программу?", true) {
			return 0
		}
		quitApp()
		return 0
	case wmDestroy:
		removeTrayIcon()
		pPostQuitMessage.Call(0)
		return 0
	}
	if msgTaskbarCreated != 0 && msg == msgTaskbarCreated { // перезапустился проводник - вернуть значок
		addTrayIcon()
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

func createControls() {
	fontUI = mkFont(15, false, "Segoe UI")
	fontBold = mkFont(17, true, "Segoe UI")
	fontMono = mkFont(14, false, "Consolas")
	hStatus = mkCtl("STATIC", "Обход выключен", ssEndEllipsis|ssNoPrefix, 0, 0, fontBold)
	hInfo = mkCtl("STATIC", "Определяю VPN и провайдера...", ssEndEllipsis|ssNoPrefix, 0, 0, fontUI)
	btn := func(id int, text string) { mkCtl("BUTTON", text, bsPushButton|wsTabStop, 0, id, fontUI) }
	btn(idOn, "Включить обход (VPN выключится)")
	btn(idVPN, "Включить обход вместе с VPN")
	btn(idOff, "Выключить всё")
	btn(idDiag, "Диагностика")
	btn(idReselect, "Подобрать заново")
	btn(idTune, "Новые сайты")
	btn(idDefender, "Защитник")
	btn(idTG, "Telegram")
	site := mkCtl("EDIT", "", esAutoHScroll|wsTabStop, wsExClientEdge, idSite, fontUI)
	sendMsg(site, emSetCueBanner, 1, uintptr(unsafe.Pointer(u16("сайт, например rutracker.org"))))
	btn(idDeep, "Глубокая проверка")
	btn(idStop, "Стоп")
	btn(idShare, "Поделиться результатом")
	mkCtl("BUTTON", "Запускать вместе с Windows", bsAutoCheckBox|wsTabStop, 0, idAuto, fontUI)
	mkCtl("BUTTON", "Сворачивать в трей", bsAutoCheckBox|wsTabStop, 0, idTray, fontUI)
	btn(idUpdate, "Проверить обновления")
	hLog = mkCtl("EDIT", "", esMultiline|esAutoVScroll|esReadOnly|wsVScroll, wsExClientEdge, 0, fontMono)
	sendMsg(hLog, emSetLimitText, 0, 0)
	if settings.Tray {
		sendMsg(ctl[idTray], bmSetCheck, 1, 0)
	}
	layout()
}

// ---------- запуск окна ----------

// activateExisting: если окно программы уже открыто - показывает его и возвращает true.
// После обновления ждёт, пока старая версия закроется.
func activateExisting(cmd string) bool {
	find := func() uintptr {
		h, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(u16(className))), 0)
		if h == 0 {
			h, _, _ = pFindWindowW.Call(uintptr(unsafe.Pointer(u16("webview"))), uintptr(unsafe.Pointer(u16(webTitle))))
		}
		return h
	}
	if strings.HasPrefix(cmd, "resume") {
		for i := 0; i < 40 && find() != 0; i++ {
			time.Sleep(250 * time.Millisecond)
		}
	}
	h := find()
	if h == 0 {
		return false
	}
	if cmd != "autostart" {
		pShowWindow.Call(h, 9)
		pShowWindow.Call(h, 5)
		pSetForegroundWindow.Call(h)
	}
	return true
}

func runClassicGUI(cmd string) {
	runtime.LockOSThread()

	hInst, _, _ = pGetModuleHandleW.Call(0)
	exe, _ := os.Executable()
	appIcon, _, _ = pExtractIconW.Call(hInst, uintptr(unsafe.Pointer(u16(exe))), 0)
	if appIcon <= 1 {
		appIcon, _, _ = pLoadIconW.Call(0, 32512)
	}
	cursor, _, _ := pLoadCursorW.Call(0, 32512)
	wc := wndClassEx{
		WndProc:    syscall.NewCallback(wndProc),
		Instance:   hInst,
		Icon:       appIcon,
		IconSm:     appIcon,
		Cursor:     cursor,
		Background: 15 + 1, // COLOR_BTNFACE
		ClassName:  u16(className),
	}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		messageBox("Не удалось создать окно: "+err.Error(), false)
		return
	}
	msgTaskbarCreated, _, _ = pRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(u16("TaskbarCreated"))))

	titleText := "dpi-bypass " + version + " - обход блокировок"
	h, _, err := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(u16(className))), uintptr(unsafe.Pointer(u16(titleText))),
		wsOverlappedWindow|wsClipChildren, 0x80000000, 0x80000000, 960, 680, 0, 0, hInst, 0)
	if h == 0 {
		messageBox("Не удалось создать окно: "+err.Error(), false)
		return
	}
	guiHwnd = h

	// вывод программы - в окно и в лог
	out = io.MultiWriter(safeWriter{guiWriter{}}, safeWriter{logFileWriter})
	statusHook = func(s string) {
		statusMu.Lock()
		statusNow = s
		statusMu.Unlock()
		postMsg(wmAppStatus, 0, 0)
	}
	addTrayIcon()
	if autostartEnabled() {
		sendMsg(ctl[idAuto], bmSetCheck, 1, 0)
	}

	hidden := cmd == "autostart" && settings.Tray && trayAdded
	if !hidden {
		pShowWindow.Call(h, 5)
		pUpdateWindow.Call(h)
	}
	pSetTimer.Call(h, 1, 30000, 0)

	banner()
	if isARM64() {
		warn("Это Windows на ARM-процессоре. Драйвер WinDivert для ARM64 официально не подписан,")
		say("      поэтому обход DPI здесь, скорее всего, не запустится. Прокси для Telegram работать будет.")
	}
	info("Выбери действие кнопками сверху. Журнал работы - здесь и в %s", logPath)
	refreshInfoAsync()
	go func() {
		if v, ok := latestVersion(); ok && newerVersion(v, version) {
			updateTo.Store(v)
			warn("Вышла новая версия %s - кнопка «Обновить до %s».", v, v)
			refreshInfoAsync()
		}
	}()

	switch {
	case cmd == "autostart":
		info("Автозапуск: включаю обход (%s).", modeName(settings.LastMode))
		startEngineAsync(settings.LastMode, false)
	case strings.HasPrefix(cmd, "resume") && len(cmd) > 6:
		m := modeWithVPN
		if cmd == "resume1" {
			m = modeNoVPN
		}
		good("Программа обновлена до версии %s - включаю обход обратно.", version)
		startEngineAsync(m, false)
	case cmd == "resume":
		good("Программа обновлена до версии %s.", version)
	}

	var m winMsg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if r, _, _ := pIsDialogMessageW.Call(h, uintptr(unsafe.Pointer(&m))); r != 0 {
			continue
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	stopActive()
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}
