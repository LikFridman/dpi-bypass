//go:build windows

package main

// Проверка окна на GitHub Actions: страница загрузилась, все разделы на месте,
// ошибок JavaScript нет; делаются снимки экрана для README.

import (
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	uitestReport = make(chan string, 4)
	uitestErrs   []string
	uitestExit   = 1
	uitestReady  = make(chan struct{}, 1)
	demoMode     bool
)

func ioMulti(ws ...io.Writer) io.Writer {
	var safe []io.Writer
	for _, w := range ws {
		safe = append(safe, safeWriter{w})
	}
	return io.MultiWriter(safe...)
}

func sortStrings(s []string) { sort.Strings(s) }

// ---------- снимок окна ----------

var (
	gdi                    = syscall.NewLazyDLL("gdi32.dll")
	usr                    = syscall.NewLazyDLL("user32.dll")
	pCreateCompatibleDC    = gdi.NewProc("CreateCompatibleDC")
	pCreateDIBSection      = gdi.NewProc("CreateDIBSection")
	pSelectObject          = gdi.NewProc("SelectObject")
	pDeleteObject          = gdi.NewProc("DeleteObject")
	pDeleteDC              = gdi.NewProc("DeleteDC")
	pBitBlt                = gdi.NewProc("BitBlt")
	pGetDC                 = usr.NewProc("GetDC")
	pReleaseDC             = usr.NewProc("ReleaseDC")
	pPrintWindow           = usr.NewProc("PrintWindow")
	pClientToScreen        = usr.NewProc("ClientToScreen")
	pSetForegroundWindowUT = usr.NewProc("SetForegroundWindow")
)

type bitmapInfoHeader struct {
	Size          uint32
	Width, Height int32
	Planes, Bits  uint16
	Compression   uint32
	SizeImage     uint32
	XPels, YPels  int32
	ClrUsed       uint32
	ClrImportant  uint32
}

func grab(hwnd uintptr, fromScreen bool) (*image.RGBA, error) {
	var r rect
	pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	w, h := r.Right, r.Bottom
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("окно без размера")
	}
	src := hwnd
	if fromScreen {
		src = 0
	}
	hdc, _, _ := pGetDC.Call(src)
	defer pReleaseDC.Call(src, hdc)
	mem, _, _ := pCreateCompatibleDC.Call(hdc)
	defer pDeleteDC.Call(mem)
	bi := bitmapInfoHeader{Size: 40, Width: w, Height: -h, Planes: 1, Bits: 32}
	var bits unsafe.Pointer
	hbm, _, _ := pCreateDIBSection.Call(hdc, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hbm == 0 || bits == nil {
		return nil, fmt.Errorf("CreateDIBSection")
	}
	defer pDeleteObject.Call(hbm)
	old, _, _ := pSelectObject.Call(mem, hbm)
	if fromScreen {
		pt := struct{ X, Y int32 }{}
		pClientToScreen.Call(hwnd, uintptr(unsafe.Pointer(&pt)))
		pBitBlt.Call(mem, 0, 0, uintptr(w), uintptr(h), hdc, uintptr(pt.X), uintptr(pt.Y), 0x00CC0020) // SRCCOPY
	} else {
		pPrintWindow.Call(hwnd, mem, 3) // PW_CLIENTONLY | PW_RENDERFULLCONTENT
	}
	pSelectObject.Call(mem, old)
	px := unsafe.Slice((*byte)(bits), int(w)*int(h)*4)
	img := image.NewRGBA(image.Rect(0, 0, int(w), int(h)))
	for i := 0; i < len(px); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = px[i+2], px[i+1], px[i], 255
	}
	return img, nil
}

// distinctColors - грубая проверка, что на снимке не пустота
func distinctColors(img *image.RGBA) int {
	seen := map[uint32]bool{}
	for i := 0; i < len(img.Pix); i += 4 * 97 {
		seen[uint32(img.Pix[i])>>4<<8|uint32(img.Pix[i+1])>>4<<4|uint32(img.Pix[i+2])>>4] = true
	}
	return len(seen)
}

func screenshot(name string) error {
	pSetForegroundWindowUT.Call(guiHwnd)
	img, err := grab(guiHwnd, false)
	if err != nil || distinctColors(img) < 20 {
		img, err = grab(guiHwnd, true)
	}
	if err != nil {
		return err
	}
	if n := distinctColors(img); n < 20 {
		return fmt.Errorf("снимок %s почти однотонный (%d цветов) - окно не отрисовалось", name, n)
	}
	dir := filepath.Join(baseDir, "docs", "screens")
	os.MkdirAll(dir, 0755)
	f, err := os.Create(filepath.Join(dir, name+".png"))
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

// ---------- демо-состояние для снимков ----------

func demoState(st uiState) uiState {
	st.Running, st.Starting, st.Busy, st.Mode = true, false, false, modeWithVPN
	st.ISP, st.VPN, st.Checked = "Ростелеком (AS12389)", "VPN: Happ (TUN, весь трафик через VPN)", "минуту назад"
	st.TgLink = "tg://proxy?server=127.0.0.1&port=1443&secret=dd0123456789abcdef0123456789abcdef"
	st.TgStats = "connections 12 (active 3) · WebSocket 12 · TCP 0 · failed 0"
	st.TgProxies = []string{"MTProto 203.0.113.7:443 (FakeTLS)"}
	st.Update = "1.5"
	st.Sites = []uiSiteRow{
		{Name: "YouTube", Kind: "ok", Label: "38 ms", Strategy: "s1 · shared", Detail: "4.2 MB/s · видео rr1---sn.googlevideo.com", Chosen: true, Via: "обход (winws)", ViaKind: "bypass", Backup: "VPN · NL Amsterdam"},
		{Name: "Discord", Kind: "ok", Label: "52 ms", Strategy: "s1 · shared", Detail: "1.8 MB/s · файл discord.com", Chosen: true, Via: "обход (winws)", ViaKind: "bypass", Backup: "VPN · NL Amsterdam"},
		{Name: "Instagram", Kind: "ok", Label: "161 ms", Strategy: "s1 · shared", Detail: "через VPN", Chosen: true, Via: "VPN · NL Amsterdam", ViaKind: "vpn", Backup: "обход (winws)"},
		{Name: "X/Twitter", Kind: "bad", Label: "none", Strategy: "s1 · shared", Detail: "throttle: обрыв после 16 КБ: замедление / обрыв по объёму (ТСПУ)", Chosen: true},
		{Name: "Rutracker", Kind: "custom", Label: "45 ms", Strategy: "custom · c41872", Chosen: true},
		{Name: "LinkedIn", Kind: "ok", Label: "88 ms", Strategy: "s1 · shared", Detail: "1.1 MB/s · файл static.licdn.com", Chosen: true},
		{Name: "Roblox", Kind: "ok", Label: "112 ms", Strategy: "u-u2 · shared", Chosen: true},
		{Name: "Telegram", Kind: "ok", Label: "140 ms", Strategy: "IP blocked", Chosen: true, Via: "WebSocket", ViaKind: "ws", Backup: "MTProto-прокси, VPN"},
	}
	st.VPNB = uiVPN{Available: true, Free: true, Warp: true, OK: 14, Total: 80, TestedAt: 1, Tested: "3 min ago", Xray: true, PAC: true,
		List: []uiVPNRow{{ID: "a1b2c3d4e5", Name: "my server", Proto: "vless", Source: "own", OK: true, Ping: 74, TG: 96, KBps: 6200, Pool: true, Own: true},
			{ID: "f6a7b8c9d0", Name: "NL Amsterdam", Proto: "vless", Source: "free", OK: true, Ping: 161, TG: 180, KBps: 2100, Pool: true}}}
	st.SitesOK, st.SitesTotal = 7, 7
	st.Missing = nil
	return st
}

func evalJS(js string) { wv.Dispatch(func() { wv.Eval(js) }) }

// runUITest проверяет страницу и делает снимки, затем закрывает окно
func runUITest() {
	fail := func(f string, a ...any) { uitestErrs = append(uitestErrs, fmt.Sprintf(f, a...)) }
	finish := func() {
		res := "OK"
		if len(uitestErrs) > 0 {
			res = "FAIL\n" + strings.Join(uitestErrs, "\n")
		} else {
			uitestExit = 0
		}
		os.WriteFile(filepath.Join(baseDir, "uitest.txt"), []byte(res+"\n"), 0644)
		wv.Dispatch(func() { wv.Terminate() })
	}
	select {
	case <-uitestReady:
	case <-time.After(40 * time.Second):
		fail("страница не загрузилась за 40 секунд")
		finish()
		return
	}
	time.Sleep(2500 * time.Millisecond)

	// проверки внутри страницы
	evalJS(`(function(){var e=[];var q=function(s){return document.querySelectorAll(s).length};
	if(q('.page')!==8)e.push('разделов '+q('.page'));
	if(q('.nv')!==8)e.push('кнопок меню '+q('.nv'));
	['home','sites','vpn','deep','dns','def','log','set'].forEach(function(p){ui.go(p);if(!document.querySelector('#p-'+p+'.on'))e.push('не открылся раздел '+p)});
	ui.go('home');
	if(!/^v\d/.test(document.querySelector("#ver").textContent))e.push("нет версии");
	if(document.querySelector('#fullLog').childElementCount<1)e.push('журнал пуст');
	if(!window.dpiCall)e.push('нет моста dpiCall');
	window.dpiCall('uitest',JSON.stringify(e));})()`)
	select {
	case r := <-uitestReport:
		var errs []string
		json.Unmarshal([]byte(r), &errs)
		for _, e := range errs {
			fail("страница: %s", e)
		}
	case <-time.After(10 * time.Second):
		fail("проверка страницы не ответила")
	}

	shots := []struct{ name, js string }{
		{"home-off", "ui.go('home')"},
		{"__demo", ""},
		{"home", "ui.go('home')"},
		{"sites", "ui.go('sites')"},
		{"deep", "ui.go('deep');document.querySelector('#deepIn').value='rutracker.org'"},
		{"vpn", "ui.go('vpn')"},
		{"settings", "ui.go('set')"},
		{"confirm", "ui.go('home');window.__push({events:[{t:'confirm',id:0,text:'Найден VPN: Happ (TUN).\\nЗакрыть его?'}]})"},
	}
	for _, s := range shots {
		if s.name == "__demo" {
			demoMode = true
			time.Sleep(1200 * time.Millisecond)
			continue
		}
		evalJS(s.js)
		time.Sleep(1500 * time.Millisecond)
		if err := screenshot(s.name); err != nil {
			fail("снимок %s: %v", s.name, err)
		}
	}
	finish()
}
