//go:build windows

package main

// Встроенный VPN на ПК (ядро Xray) и способы для каждого сервиса - как на Android:
//   - свои ключи и подписки, бесплатный Cloudflare WARP, бесплатные серверы из публичных списков;
//   - серверы проверяются по-настоящему (сайт и Telegram через каждый), лучшие держит Xray на
//     локальных портах SOCKS;
//   - маршрутизатор (тот же, что на Android) получает соединения сервисов и ведёт их основным
//     способом (обход - соединение напрямую, его маскирует winws; или VPN), при сбое - запасным;
//   - браузеры и Discord попадают в маршрутизатор через системный PAC-файл (только домены
//     выбранных сервисов, остальное - напрямую); Telegram Desktop - через свой локальный прокси.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"dpibypass/router"
	"dpibypass/tg"
	"dpibypass/vpn"
)

const (
	xrayVersion  = "v26.10.31"
	xrayExeName  = "dpi-bypass-xray.exe" // своё имя: не путать с Xray других программ (v2rayN и т.п.)
	vpnPortBase  = 2081
	vpnPoolSize  = 4
	pcRouterAddr = "127.0.0.1:1090"
	pcPACAddr    = "127.0.0.1:1092"
)

var defaultVPNSources = []string{
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
}

// vpnState - настройки и результаты проверки (vpn.json)
type vpnState struct {
	Own      []string          `json:"own,omitempty"`    // свои ключи
	Subs     []string          `json:"subs,omitempty"`   // ссылки на подписки
	NoFree   bool              `json:"no_free,omitempty"` // бесплатные серверы выключены
	NoWarp   bool              `json:"no_warp,omitempty"` // WARP выключен
	Warp     []string          `json:"warp,omitempty"`   // ссылки зарегистрированного WARP
	Sources  []string          `json:"sources,omitempty"`
	Results  []vpn.Result      `json:"results,omitempty"`
	TestedAt int64             `json:"tested_at,omitempty"`
	Routes   map[string]string `json:"routes,omitempty"` // способ, выбранный вручную: vpn, vpn:<id>, bypass, tg-ws, tg-proxy
}

var (
	vpnMu      sync.Mutex
	vpnSt      vpnState
	vpnLoaded  bool
	vpnTesting atomic.Bool
	vpnProg    atomic.Value // string

	pcRouterMu sync.Mutex
	pcRouter   *router.Router
	pcPool     []vpn.Slot // с чем запущен маршрутизатор
	pcPACOn    bool
	pacSrv     *http.Server
	pacMu      sync.Mutex
	pacBody    string
	pacVer     int
	strayOnce  sync.Once
)

func vpnPath() string { return filepath.Join(dataDir, "vpn.json") }

// vpnLoad - состояние из файла (один раз); вызывать под vpnMu
func vpnLoad() {
	if vpnLoaded {
		return
	}
	vpnLoaded = true
	if b, err := os.ReadFile(vpnPath()); err == nil {
		json.Unmarshal(b, &vpnSt)
	}
}

// vpnSave - под vpnMu
func vpnSave() {
	b, _ := json.MarshalIndent(vpnSt, "", "  ")
	tmp := vpnPath() + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		os.Remove(vpnPath())
		os.Rename(tmp, vpnPath())
	}
}

func vpnGet() vpnState {
	vpnMu.Lock()
	defer vpnMu.Unlock()
	vpnLoad()
	s := vpnSt
	s.Own = append([]string(nil), vpnSt.Own...)
	s.Subs = append([]string(nil), vpnSt.Subs...)
	s.Results = append([]vpn.Result(nil), vpnSt.Results...)
	s.Routes = map[string]string{}
	for k, v := range vpnSt.Routes {
		s.Routes[k] = v
	}
	return s
}

func vpnUpdate(fn func(s *vpnState)) {
	vpnMu.Lock()
	vpnLoad()
	fn(&vpnSt)
	vpnSave()
	vpnMu.Unlock()
}

func setVPNSources(l []string) {
	var ok []string
	for _, u := range l {
		if strings.HasPrefix(u, "https://") {
			ok = append(ok, u)
		}
	}
	if len(ok) > 0 {
		vpnUpdate(func(s *vpnState) { s.Sources = ok })
	}
}

// vpnID - номер сервера, как у ядра (sha1 ссылки без названия)
func vpnID(link string) string {
	if s, err := vpn.Parse(link); err == nil {
		return s.ID
	}
	return ""
}

// ---------- Xray ----------

func xrayPath() string { return filepath.Join(dataDir, "xray", xrayVersion, xrayExeName) }

// ensureXray скачивает Xray для Windows с GitHub (проверка SHA-256 из .dgst того же выпуска)
func ensureXray() (string, error) {
	p := xrayPath()
	if fileExists(p) {
		return p, nil
	}
	base := "https://github.com/XTLS/Xray-core/releases/download/" + xrayVersion + "/"
	cl := &http.Client{Timeout: 120 * time.Second}
	get := func(u string, max int64) ([]byte, error) {
		resp, err := cl.Get(u)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, max))
	}
	info("VPN: скачиваю Xray %s (ядро VPN, ~15 МБ)...", xrayVersion)
	dg, err := get(base+"Xray-windows-64.zip.dgst", 64<<10)
	if err != nil {
		return "", fmt.Errorf("Xray: контрольная сумма не скачалась: %v", err)
	}
	want := ""
	for _, l := range strings.Split(string(dg), "\n") {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(l)), "SHA2-256") {
			f := strings.Fields(l)
			want = strings.ToLower(f[len(f)-1])
			break
		}
	}
	if len(want) != 64 {
		return "", fmt.Errorf("Xray: в .dgst нет SHA2-256")
	}
	z, err := get(base+"Xray-windows-64.zip", 80<<20)
	if err != nil {
		return "", fmt.Errorf("Xray не скачался: %v", err)
	}
	sum := sha256.Sum256(z)
	if hex.EncodeToString(sum[:]) != want {
		return "", fmt.Errorf("Xray: контрольная сумма не совпала - файл повреждён или подменён")
	}
	zr, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		return "", err
	}
	for _, f := range zr.File {
		if strings.EqualFold(filepath.Base(f.Name), "xray.exe") {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}
			b, err := io.ReadAll(io.LimitReader(rc, 100<<20))
			rc.Close()
			if err != nil {
				return "", err
			}
			os.MkdirAll(filepath.Dir(p), 0755)
			if err := os.WriteFile(p+".part", b, 0755); err != nil {
				return "", err
			}
			os.Remove(p)
			if err := os.Rename(p+".part", p); err != nil {
				return "", err
			}
			good("VPN: Xray %s скачан", xrayVersion)
			return p, nil
		}
	}
	return "", fmt.Errorf("Xray: в архиве нет xray.exe")
}

// xraySetup - окно не показывать
func xraySetup(c *exec.Cmd) { c.SysProcAttr = hiddenProcAttr() }

// killStrayXray - свой Xray, оставшийся после аварийного завершения программы
func killStrayXray() {
	if !runningProcesses()[strings.ToLower(xrayExeName)] {
		return
	}
	c := exec.Command("taskkill", "/F", "/IM", xrayExeName)
	c.SysProcAttr = hiddenProcAttr()
	c.Run()
	time.Sleep(300 * time.Millisecond)
}

// ---------- списки и проверка серверов ----------

var vpnSchemes = []string{"vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "wireguard://", "wg://"}

func isVPNLink(l string) bool {
	ll := strings.ToLower(l)
	for _, s := range vpnSchemes {
		if strings.HasPrefix(ll, s) {
			return true
		}
	}
	return false
}

// parseVPNText - ссылки из текста подписки (по строке или целиком в base64)
func parseVPNText(text string) []string {
	t := strings.TrimSpace(text)
	if !strings.Contains(t, "://") {
		clean := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
				return -1
			}
			return r
		}, t)
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if d, err := enc.DecodeString(clean); err == nil && strings.Contains(string(d), "://") {
				t = string(d)
				break
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range strings.Split(t, "\n") {
		l = strings.TrimSpace(l)
		if isVPNLink(l) && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// fetchText - текст по ссылке (GitHub - с запасным адресом jsDelivr)
func fetchText(u string) (string, error) {
	urls := []string{u}
	if strings.HasPrefix(u, "https://raw.githubusercontent.com/") {
		p := strings.SplitN(strings.TrimPrefix(u, "https://raw.githubusercontent.com/"), "/", 4)
		if len(p) == 4 {
			urls = append(urls, "https://cdn.jsdelivr.net/gh/"+p[0]+"/"+p[1]+"@"+p[2]+"/"+p[3])
		}
	}
	cl := &http.Client{Timeout: 12 * time.Second}
	var last error
	for _, x := range urls {
		resp, err := cl.Get(x)
		if err != nil {
			last = err
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err == nil && resp.StatusCode == 200 && len(b) > 0 {
			return string(b), nil
		}
		last = fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return "", last
}

// vpnAdd - свои ключи и подписки из текста; итог для пользователя
func vpnAdd(text string) string {
	var keys, subs []string
	for _, f := range strings.Fields(text) {
		switch {
		case isVPNLink(f):
			if _, err := vpn.Parse(f); err != nil {
				return "Ключ не разобран: " + err.Error()
			}
			keys = append(keys, f)
		case strings.HasPrefix(f, "https://") || strings.HasPrefix(f, "http://"):
			subs = append(subs, f)
		}
	}
	if len(keys) == 0 && len(subs) == 0 {
		return "Не нашёл ключей (vless://, vmess://, trojan://, ss://, hysteria2://, wireguard://) или ссылок на подписку"
	}
	vpnUpdate(func(s *vpnState) {
		s.Own = uniq(append(s.Own, keys...))
		s.Subs = uniq(append(s.Subs, subs...))
	})
	var parts []string
	if len(keys) > 0 {
		parts = append(parts, fmt.Sprintf("ключей: %d", len(keys)))
	}
	if len(subs) > 0 {
		parts = append(parts, fmt.Sprintf("подписок: %d", len(subs)))
	}
	return "Добавлено " + strings.Join(parts, ", ") + " - проверяю"
}

func uniq(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range l {
		if x = strings.TrimSpace(x); x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// vpnRemove - свой ключ (по номеру) или подписку (по ссылке)
func vpnRemove(id string) {
	vpnUpdate(func(s *vpnState) {
		var own, subs []string
		for _, l := range s.Own {
			if vpnID(l) != id && l != id {
				own = append(own, l)
			}
		}
		for _, l := range s.Subs {
			if l != id {
				subs = append(subs, l)
			}
		}
		var res []vpn.Result
		for _, r := range s.Results {
			if r.ID != id {
				res = append(res, r)
			}
		}
		s.Own, s.Subs, s.Results = own, subs, res
	})
}

// usableVPN - сервер ещё в настройках (бесплатные не выключены, свой не удалён)
func usableVPN(s *vpnState, r vpn.Result) bool {
	switch r.Source {
	case "free":
		return !s.NoFree
	case "warp":
		return !s.NoWarp
	case "own":
		for _, l := range s.Own {
			if vpnID(l) == r.ID {
				return true
			}
		}
		return false
	}
	return true
}

// vpnBest - рабочие серверы, лучшие первыми (свои - выше при близкой задержке)
func vpnBest(s *vpnState, forTG bool) []vpn.Result {
	score := func(r vpn.Result) float64 {
		v := float64(r.Ping)
		if forTG {
			v = float64(r.TG)
		}
		if r.KBps > 0 && r.KBps < 300 {
			v += 400
		}
		if r.Source == "own" || r.Source == "sub" {
			v *= 0.6
		}
		return v
	}
	var out []vpn.Result
	for _, r := range s.Results {
		if r.OK && (!forTG || r.TG > 0) && usableVPN(s, r) {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return score(out[a]) < score(out[b]) })
	return out
}

// vpnPool - серверы для Xray: выбранные вручную, лучшие для сайтов и для Telegram
func vpnPool(s *vpnState) []vpn.Slot {
	pick := []string{}
	has := map[string]bool{}
	add := func(l string) {
		if !has[l] {
			has[l] = true
			pick = append(pick, l)
		}
	}
	manual := 0
	for _, v := range s.Routes {
		if id := strings.TrimPrefix(v, "vpn:"); id != v {
			for _, r := range s.Results {
				if r.ID == id && r.OK && usableVPN(s, r) && manual < 2 {
					add(r.Link)
					manual++
				}
			}
		}
	}
	b, t := vpnBest(s, false), vpnBest(s, true)
	for i := 0; i < 2 && i < len(b); i++ {
		add(b[i].Link)
	}
	for i := 0; i < 2 && i < len(t); i++ {
		add(t[i].Link)
	}
	for _, r := range b {
		if len(pick) >= vpnPoolSize+manual {
			break
		}
		add(r.Link)
	}
	var slots []vpn.Slot
	for i, l := range pick {
		if i >= vpnPoolSize+manual {
			break
		}
		sv, err := vpn.Parse(l)
		if err != nil {
			continue
		}
		slots = append(slots, vpn.Slot{Server: sv, Port: vpnPortBase + i})
	}
	return slots
}

// vpnTestAsync - проверить серверы (quick - только свои и прежние рабочие); done - итог
func vpnTestAsync(quick bool, done func(string)) {
	if !vpnTesting.CompareAndSwap(false, true) {
		if done != nil {
			done("Проверка серверов уже идёт")
		}
		return
	}
	go func() {
		defer func() {
			vpnTesting.Store(false)
			vpnProg.Store("")
			if e := recover(); e != nil {
				bad("VPN: сбой проверки: %v", e)
			}
		}()
		msg := vpnTest(quick)
		if done != nil {
			done(msg)
		}
	}()
}

func vpnTest(quick bool) string {
	xr, err := ensureXray()
	if err != nil {
		bad("%v", err)
		return err.Error()
	}
	s := vpnGet()
	links := []string{}
	src := map[string]string{}
	add := func(l, from string) {
		if _, ok := src[l]; !ok {
			src[l] = from
			links = append(links, l)
		}
	}
	for _, l := range s.Own {
		add(l, "own")
	}
	vpnProg.Store("загружаю списки серверов")
	for _, u := range s.Subs {
		t, err := fetchText(u)
		if err != nil {
			warn("VPN: подписка не загрузилась (%v)", err)
			continue
		}
		for i, l := range parseVPNText(t) {
			if i >= 100 {
				break
			}
			add(l, "sub")
		}
	}
	if !s.NoWarp {
		if len(s.Warp) == 0 && !quick {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			acc, err := vpn.RegisterWarp(ctx, nil)
			cancel()
			if err != nil {
				info("VPN: WARP не зарегистрировался (%v)", err)
			} else {
				s.Warp = acc.Links()
				vpnUpdate(func(x *vpnState) { x.Warp = s.Warp })
				good("VPN: бесплатный Cloudflare WARP зарегистрирован")
			}
		}
		for _, l := range s.Warp {
			add(l, "warp")
		}
	}
	if !s.NoFree {
		for _, r := range s.Results {
			if r.OK && r.Source == "free" {
				add(r.Link, "free")
			}
		}
		if !quick {
			srcs := s.Sources
			if len(srcs) == 0 {
				srcs = defaultVPNSources
			}
			var fresh []string
			for _, u := range srcs {
				if t, err := fetchText(u); err == nil {
					l := parseVPNText(t)
					if len(l) > 60 {
						l = l[:60]
					}
					fresh = append(fresh, l...)
				}
			}
			n := 0
			for _, l := range links {
				if src[l] == "free" {
					n++
				}
			}
			// перемешать, чтобы каждый раз пробовать разные
			r := time.Now().UnixNano()
			for i := len(fresh) - 1; i > 0; i-- {
				r = r*6364136223846793005 + 1442695040888963407
				j := int(uint64(r)>>33) % (i + 1)
				fresh[i], fresh[j] = fresh[j], fresh[i]
			}
			for _, l := range fresh {
				if n >= 80 {
					break
				}
				if _, ok := src[l]; !ok {
					add(l, "free")
					n++
				}
			}
		}
	}
	if len(links) == 0 {
		return "Нет серверов: добавь свой ключ или включи бесплатные"
	}
	var list []*vpn.Server
	var bads []vpn.Result
	for _, l := range links {
		sv, err := vpn.Parse(l)
		if err != nil {
			bads = append(bads, vpn.Result{ID: vpnID(l), Err: "ссылка: " + err.Error(), Link: l, Source: src[l]})
			continue
		}
		sv.Source = src[l]
		list = append(list, sv)
	}
	vpnProg.Store(fmt.Sprintf("проверяю %d серверов", len(list)))
	info("VPN: проверяю серверов %d…", len(list))
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	res := vpn.Test(ctx, xr, list, vpn.TestOpts{Telegram: true, Speed: 4, Setup: xraySetup})
	for i := range res {
		if i < len(list) {
			res[i].Link = list[i].Link
			if res[i].Source == "" {
				res[i].Source = list[i].Source
			}
		}
	}
	res = append(res, bads...)
	okN, tgN := 0, 0
	for _, r := range res {
		if r.OK {
			okN++
		}
		if r.TG > 0 {
			tgN++
		}
	}
	vpnUpdate(func(x *vpnState) {
		// прежние результаты своих, которых не было в этой проверке, не теряем
		keep := res
		for _, p := range x.Results {
			if p.Source == "free" || src[p.Link] != "" {
				continue
			}
			found := false
			for _, r := range res {
				if r.ID == p.ID {
					found = true
					break
				}
			}
			if !found && p.Source != "" {
				keep = append(keep, p)
			}
		}
		x.Results = keep
		x.TestedAt = time.Now().Unix()
	})
	st := vpnGet()
	msg := fmt.Sprintf("работают %d из %d (Telegram через %d)", okN, len(res), tgN)
	if b := vpnBest(&st, false); len(b) > 0 {
		msg += fmt.Sprintf(" · лучший %s %d ms", short(b[0].Name, 30), b[0].Ping)
	}
	good("VPN: %s", msg)
	return msg
}

func short(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// ---------- маршрутизатор ----------

// svcUpstreams - способы сервиса по порядку (основной, затем запасные) и «самый быстрый»
func svcUpstreams(s *vpnState, cfg *Config, name string, pool []vpn.Slot) ([]string, bool) {
	if cfg != nil && cfg.Pins[name] == NoneID {
		return []string{router.UpDirect}, false
	}
	isTG := name == "Telegram"
	ports := func(forTG bool) []string {
		var out []string
		for _, r := range vpnBest(s, forTG) {
			for _, sl := range pool {
				if sl.Server.Link == r.Link {
					out = append(out, fmt.Sprintf("127.0.0.1:%d", sl.Port))
				}
			}
			if len(out) >= 2 {
				break
			}
		}
		return out
	}
	vps := ports(isTG)
	bp := router.UpDirect // обход на ПК - соединение напрямую, его маскирует winws
	route := s.Routes[name]
	var ups []string
	fastest := false
	switch {
	case route == "vpn":
		ups = append(append(ups, vps...), bp)
	case strings.HasPrefix(route, "vpn:"):
		id := strings.TrimPrefix(route, "vpn:")
		for _, sl := range pool {
			if sl.Server.ID == id {
				ups = append(ups, fmt.Sprintf("127.0.0.1:%d", sl.Port))
			}
		}
		ups = append(append(ups, vps...), bp)
	case route == "bypass":
		ups = append([]string{bp}, vps...)
	case cfg != nil && hasKey(cfg.Unfixable, name) && len(vps) > 0:
		// блок по IP - стратегией не исправить, сначала VPN
		ups = append(append(ups, vps...), bp)
	default:
		ups = append([]string{bp}, vps...)
	}
	return dedup(ups), fastest
}

func hasKey(m map[string]string, k string) bool { _, ok := m[k]; return ok }

func dedup(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range l {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// vpnUpName - понятное имя способа
func vpnUpName(s *vpnState, pool []vpn.Slot, up string) string {
	if up == router.UpDirect {
		return "обход (winws)"
	}
	for _, sl := range pool {
		if fmt.Sprintf("127.0.0.1:%d", sl.Port) == up {
			n := sl.Server.Label()
			for _, r := range s.Results {
				if r.ID == sl.Server.ID && r.Name != "" {
					n = r.Name
				}
			}
			return "VPN · " + n
		}
	}
	return up
}

// pcRouterStart (пере)запускает маршрутизатор и Xray с текущими серверами и способами.
// Нужен, только если есть рабочие серверы VPN; иначе - выключен, PAC не ставится.
func pcRouterStart(cfg *Config, svcs []Service) {
	pcRouterMu.Lock()
	defer pcRouterMu.Unlock()
	pcRouterStopLocked()
	if runMode != modeNoVPN {
		return // VPN - у внешнего клиента
	}
	s := vpnGet()
	pool := vpnPool(&s)
	if len(pool) == 0 {
		return
	}
	xr, err := ensureXray()
	if err != nil {
		bad("%v", err)
		return
	}
	// свой Xray после аварийного завершения - один раз за запуск и не во время проверки серверов
	if !vpnTesting.Load() {
		strayOnce.Do(killStrayXray)
	}
	rc := router.Config{Listen: pcRouterAddr, Default: router.UpDirect, Xray: xr, Names: map[string]string{}}
	for _, sl := range pool {
		rc.VPN = append(rc.VPN, router.VPNSlot{Link: sl.Server.Link, Port: sl.Port})
	}
	var domains []string
	for _, sv := range svcs {
		if sv.Name == "Telegram" {
			continue // Telegram Desktop - через свой локальный прокси (у него свои способы)
		}
		if !serviceActiveIn(cfg, sv.Name) {
			continue
		}
		ups, fastest := svcUpstreams(&s, cfg, sv.Name, pool)
		for _, u := range ups {
			rc.Names[u] = vpnUpName(&s, pool, u)
		}
		check := ""
		if len(sv.Probes) > 0 {
			check = sv.Probes[0]
		}
		rc.Groups = append(rc.Groups, router.Group{Name: sv.Name, Upstreams: ups, Domains: sv.Domains, Check: check, Fastest: fastest})
		domains = append(domains, sv.Domains...)
	}
	r := router.New(rc)
	r.Log = func(format string, a ...any) {
		m := fmt.Sprintf(format, a...)
		// в журнал - только переключения способов и VPN (остальное - шум)
		if strings.Contains(m, "перевожу") || strings.Contains(m, "снова работает") || strings.Contains(m, "теперь через") || strings.HasPrefix(m, "VPN") {
			info("%s %s", ts(), m)
		}
	}
	r.XraySetup = xraySetup
	if err := r.Listen(); err != nil {
		bad("VPN: маршрутизатор не запустился: %v", err)
		return
	}
	pcRouter = r
	pcPool = pool
	if err := pacSet(domains); err != nil {
		warn("VPN: системный прокси (PAC) не включён: %v", err)
	}
	good("VPN: работает (%d серверов) - сервисы с запасным способом идут через маршрутизатор", len(pool))
}

func pcRouterStop() {
	pcRouterMu.Lock()
	defer pcRouterMu.Unlock()
	pcRouterStopLocked()
}

func pcRouterStopLocked() {
	pacUnset()
	if pcRouter != nil {
		pcRouter.Close()
		pcRouter = nil
	}
	pcPool = nil
}

// pcRefreshVPN - после проверки серверов или смены способа: перезапуск, только если что-то поменялось
func pcRefreshVPN(force bool) {
	if !engRunning.Load() {
		return
	}
	s := vpnGet()
	pool := vpnPool(&s)
	pcRouterMu.Lock()
	same := len(pool) == len(pcPool)
	for i := 0; same && i < len(pool); i++ {
		same = pool[i].Server.Link == pcPool[i].Server.Link && pool[i].Port == pcPool[i].Port
	}
	pcRouterMu.Unlock()
	if same && !force {
		return
	}
	pcRouterStart(loadConfigCached(), cachedServices())
}

// vpnMaybeRefresh - проверить серверы, если давно не проверялись (первый раз - сразу), и
// перезапустить маршрутизатор, если лучшие серверы поменялись
func vpnMaybeRefresh() {
	if runMode != modeNoVPN || vpnTesting.Load() {
		return
	}
	s := vpnGet()
	if s.TestedAt > 0 && time.Since(time.Unix(s.TestedAt, 0)) < 6*time.Hour {
		return
	}
	vpnTestAsync(false, func(string) { pcRefreshVPN(false) })
}

// pcRoutes - состояние способов сервисов (nil - маршрутизатор не работает)
func pcRoutes() map[string]router.RouteInfo {
	pcRouterMu.Lock()
	r := pcRouter
	pcRouterMu.Unlock()
	if r == nil {
		return nil
	}
	m := map[string]router.RouteInfo{}
	for _, ri := range r.Routes() {
		m[ri.Name] = ri
	}
	return m
}

func pcCheckNow(name string) map[string]router.RouteInfo {
	pcRouterMu.Lock()
	r := pcRouter
	pcRouterMu.Unlock()
	if r == nil {
		return nil
	}
	m := map[string]router.RouteInfo{}
	for _, ri := range r.CheckNow(name) {
		m[ri.Name] = ri
	}
	return m
}

// vpnSocksForTG - локальные порты Xray для Telegram (лучшие для Telegram первыми)
func vpnSocksForTG() []string {
	pcRouterMu.Lock()
	pool := append([]vpn.Slot(nil), pcPool...)
	pcRouterMu.Unlock()
	if len(pool) == 0 {
		return nil
	}
	s := vpnGet()
	var out []string
	if id := strings.TrimPrefix(s.Routes["Telegram"], "vpn:"); id != s.Routes["Telegram"] {
		for _, sl := range pool {
			if sl.Server.ID == id {
				out = append(out, fmt.Sprintf("127.0.0.1:%d", sl.Port))
			}
		}
	}
	for _, r := range vpnBest(&s, true) {
		for _, sl := range pool {
			if sl.Server.Link == r.Link {
				out = append(out, fmt.Sprintf("127.0.0.1:%d", sl.Port))
			}
		}
	}
	return dedup(out)
}

// ---------- системный прокси (PAC) ----------

var (
	wininet                = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

const inetKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func pacBackupPath() string { return filepath.Join(dataDir, "proxy-backup.json") }

// pacSet - PAC с доменами сервисов: они идут в маршрутизатор (при его отказе - напрямую)
func pacSet(domains []string) error {
	if len(domains) == 0 {
		return nil
	}
	cur := regQuery(inetKey, "AutoConfigURL")
	if cur != "" && !strings.HasPrefix(cur, "http://"+pcPACAddr+"/") {
		return fmt.Errorf("уже задан другой PAC (%s) - не трогаю", cur)
	}
	if regQuery(inetKey, "ProxyEnable") == "0x1" {
		return fmt.Errorf("включён другой системный прокси - не трогаю")
	}
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n  host = host.toLowerCase();\n  var d = [")
	seen := map[string]bool{}
	first := true
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] || strings.ContainsAny(d, `"\`) {
			continue
		}
		seen[d] = true
		if !first {
			b.WriteString(",")
		}
		first = false
		b.WriteString(`"` + d + `"`)
	}
	b.WriteString("];\n  for (var i = 0; i < d.length; i++) {\n    if (host == d[i] || dnsDomainIs(host, \".\" + d[i])) return \"SOCKS5 " + pcRouterAddr + "; SOCKS " + pcRouterAddr + "; DIRECT\";\n  }\n  return \"DIRECT\";\n}\n")
	pacMu.Lock()
	pacBody = b.String()
	pacVer++
	ver := pacVer
	pacMu.Unlock()
	if err := pacServe(); err != nil {
		return err
	}
	if !fileExists(pacBackupPath()) {
		bk, _ := json.Marshal(map[string]string{"AutoConfigURL": cur})
		os.WriteFile(pacBackupPath(), bk, 0644)
	}
	u := fmt.Sprintf("http://%s/proxy.pac?v=%d", pcPACAddr, ver)
	if err := regSet(inetKey, "AutoConfigURL", u); err != nil {
		return err
	}
	pcPACOn = true
	inetNotify()
	return nil
}

func pacServe() error {
	if pacSrv != nil {
		return nil
	}
	ln, err := net.Listen("tcp", pcPACAddr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy.pac", func(w http.ResponseWriter, q *http.Request) {
		pacMu.Lock()
		body := pacBody
		pacMu.Unlock()
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-cache")
		io.WriteString(w, body)
	})
	pacSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go pacSrv.Serve(ln)
	return nil
}

// pacUnset - вернуть системный прокси как был
func pacUnset() {
	if !pcPACOn && !fileExists(pacBackupPath()) {
		return
	}
	prev := ""
	if b, err := os.ReadFile(pacBackupPath()); err == nil {
		var m map[string]string
		if json.Unmarshal(b, &m) == nil {
			prev = m["AutoConfigURL"]
		}
	}
	cur := regQuery(inetKey, "AutoConfigURL")
	if strings.HasPrefix(cur, "http://"+pcPACAddr+"/") || cur == "" {
		if prev != "" {
			regSet(inetKey, "AutoConfigURL", prev)
		} else {
			regDelete(inetKey, "AutoConfigURL")
		}
		inetNotify()
	}
	os.Remove(pacBackupPath())
	pcPACOn = false
}

// restorePACOnStart - программа в прошлый раз завершилась аварийно: вернуть системный прокси
func restorePACOnStart() {
	if fileExists(pacBackupPath()) {
		pacUnset()
		info("Системный прокси возвращён как был (программа в прошлый раз закрылась аварийно)")
	}
}

func inetNotify() {
	procInternetSetOptionW.Call(0, 39, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	procInternetSetOptionW.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
}

func regQuery(key, name string) string {
	c := exec.Command("reg", "query", key, "/v", name)
	c.SysProcAttr = hiddenProcAttr()
	out, err := c.Output()
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && strings.EqualFold(f[0], name) {
			return strings.Join(f[2:], " ")
		}
	}
	return ""
}

func regSet(key, name, val string) error {
	c := exec.Command("reg", "add", key, "/v", name, "/t", "REG_SZ", "/d", val, "/f")
	c.SysProcAttr = hiddenProcAttr()
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("reg add: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func regDelete(key, name string) {
	c := exec.Command("reg", "delete", key, "/v", name, "/f")
	c.SysProcAttr = hiddenProcAttr()
	c.Run()
}

// ---------- для страницы ----------

type uiVPNRow struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Proto  string `json:"proto"`
	Source string `json:"source"`
	OK     bool   `json:"ok"`
	Ping   int    `json:"ping"`
	TG     int    `json:"tg"`
	KBps   int    `json:"kbps"`
	Err    string `json:"err"`
	Pool   bool   `json:"pool"`
	Own    bool   `json:"own"`
}

type uiVPN struct {
	Available bool       `json:"available"`
	Testing   bool       `json:"testing"`
	Progress  string     `json:"progress"`
	Free      bool       `json:"free"`
	Warp      bool       `json:"warp"`
	Subs      []string   `json:"subs"`
	TestedAt  int64      `json:"testedAt"`
	Tested    string     `json:"tested"`
	List      []uiVPNRow `json:"list"`
	OK        int        `json:"ok"`
	Total     int        `json:"total"`
	Xray      any        `json:"xray"`
	PAC       bool       `json:"pac"`
}

func vpnUIState() uiVPN {
	s := vpnGet()
	pcRouterMu.Lock()
	inPool := map[string]bool{}
	for _, sl := range pcPool {
		inPool[sl.Server.ID] = true
	}
	r := pcRouter
	pac := pcPACOn
	pcRouterMu.Unlock()
	u := uiVPN{Available: true, Testing: vpnTesting.Load(), Free: !s.NoFree, Warp: !s.NoWarp, Subs: s.Subs, TestedAt: s.TestedAt, PAC: pac}
	if p, ok := vpnProg.Load().(string); ok {
		u.Progress = p
	}
	if s.TestedAt > 0 {
		u.Tested = ago(time.Unix(s.TestedAt, 0))
	}
	if r != nil {
		u.Xray = r.VPNAlive()
	}
	ownIDs := map[string]bool{}
	for _, l := range s.Own {
		id := vpnID(l)
		ownIDs[id] = true
		row := uiVPNRow{ID: id, Proto: strings.SplitN(l, "://", 2)[0], Source: "own", Own: true, Err: "не проверен", Pool: inPool[id]}
		if sv, err := vpn.Parse(l); err == nil {
			row.Name = sv.Label()
		}
		for _, x := range s.Results {
			if x.ID == id {
				row.OK, row.Ping, row.TG, row.KBps, row.Err = x.OK, x.Ping, x.TG, x.KBps, x.Err
				if x.Name != "" {
					row.Name = x.Name
				}
			}
		}
		u.List = append(u.List, row)
	}
	var rest []vpn.Result
	for _, x := range s.Results {
		if x.OK && usableVPN(&s, x) {
			u.OK++
			if !ownIDs[x.ID] {
				rest = append(rest, x)
			}
		}
	}
	u.Total = len(s.Results)
	sort.SliceStable(rest, func(a, b int) bool { return rest[a].Ping < rest[b].Ping })
	for i, x := range rest {
		if i >= 30 {
			break
		}
		u.List = append(u.List, uiVPNRow{ID: x.ID, Name: x.Name, Proto: x.Proto, Source: x.Source, OK: true, Ping: x.Ping, TG: x.TG, KBps: x.KBps, Pool: inPool[x.ID]})
	}
	return u
}

// vpnSummaryReport - для отчёта: без ссылок (в них пароли серверов)
func vpnSummaryReport() map[string]any {
	s := vpnGet()
	var best []map[string]any
	for i, r := range vpnBest(&s, false) {
		if i >= 6 {
			break
		}
		best = append(best, map[string]any{"name": r.Name, "proto": r.Proto, "source": r.Source, "ping": r.Ping, "tg": r.TG, "kbps": r.KBps})
	}
	ok := 0
	errs := map[string]int{}
	for _, r := range s.Results {
		if r.OK {
			ok++
		} else {
			e := r.Err
			if len(e) > 40 {
				e = e[:40]
			}
			errs[e]++
		}
	}
	u := vpnUIState()
	return map[string]any{"ok": ok, "total": len(s.Results), "own": len(s.Own), "subs": len(s.Subs), "free": !s.NoFree, "warp": !s.NoWarp,
		"tested_at": s.TestedAt, "pool": len(pcPool), "xray": u.Xray, "pac": u.PAC, "best": best, "errors": errs, "routes_manual": s.Routes}
}

// ---------- окно сервиса: способы ----------

// tgChecks - последние проверки способов Telegram (у Telegram Desktop - свой локальный прокси)
var (
	tgChkMu sync.Mutex
	tgChk   = map[string]router.UpInfo{}
	tgChkAt = map[string]time.Time{}
)

// checkTelegramWays - проверить способы Telegram: WebSocket, MTProto-прокси, VPN (как приложение - MTProto к DC2)
func checkTelegramWays() {
	type res struct {
		up, name string
		ms       int
		err      error
	}
	var jobs []func() res
	jobs = append(jobs, func() res {
		d, err := tg.CheckWS(func(addr string) (net.Conn, error) { return newDialer(8*time.Second).Dial("tcp4", addr) }, 10*time.Second)
		return res{"tg-ws", "WebSocket", int(d.Milliseconds()), err}
	})
	if ups := tgUpstreams(); len(ups) > 0 {
		jobs = append(jobs, func() res {
			var last error
			for i, u := range ups {
				if i >= 3 {
					break
				}
				d, err := tg.CheckUpstream(u, 8*time.Second)
				if err == nil {
					return res{"tg-proxy", "MTProto-прокси", int(d.Milliseconds()), nil}
				}
				last = err
			}
			return res{"tg-proxy", "MTProto-прокси", 0, last}
		})
	}
	for _, sk := range vpnSocksForTG() {
		sk := sk
		jobs = append(jobs, func() res {
			d, err := tg.CheckDC(func(addr string) (net.Conn, error) { return tg.SocksDial(sk, addr) }, 2, 10*time.Second)
			return res{sk, "VPN", int(d.Milliseconds()), err}
		})
	}
	ch := make(chan res, len(jobs))
	for _, j := range jobs {
		go func(j func() res) { ch <- j() }(j)
	}
	for range jobs {
		r := <-ch
		ui := router.UpInfo{Up: r.up, Name: r.name, OK: r.err == nil, Ping: r.ms}
		if r.err != nil {
			ui.Err = shortErr(r.err)
		}
		tgChkMu.Lock()
		tgChk[r.up], tgChkAt[r.up] = ui, time.Now()
		tgChkMu.Unlock()
	}
}

// routeSheet - способы сервиса для окна: состояние (по маршрутизатору), выбранный вручную, серверы VPN
func routeSheet(svc string) map[string]any {
	s := vpnGet()
	isTG := svc == "Telegram"
	var ups []router.UpInfo
	active := ""
	if isTG {
		// порядок как в tgRoutes; активный - первый рабочий
		order := []string{"tg-ws", "tg-proxy"}
		vs := vpnSocksForTG()
		if r := s.Routes["Telegram"]; r == "vpn" || strings.HasPrefix(r, "vpn:") {
			order = append(append([]string{}, vs...), order...)
		} else if r == "tg-proxy" {
			order = append([]string{"tg-proxy", "tg-ws"}, vs...)
		} else {
			order = append(order, vs...)
		}
		tgChkMu.Lock()
		for _, up := range order {
			u, ok := tgChk[up]
			if !ok {
				u = router.UpInfo{Up: up, Name: map[string]string{"tg-ws": "WebSocket", "tg-proxy": "MTProto-прокси"}[up], Age: -1}
				if u.Name == "" {
					u.Name = "VPN"
				}
			} else {
				u.Age = int(time.Since(tgChkAt[up]).Seconds())
			}
			if active == "" && (u.OK || !ok) {
				active, u.Active = up, true
			}
			ups = append(ups, u)
		}
		tgChkMu.Unlock()
	} else if ri, ok := pcRoutes()[svc]; ok {
		ups, active = ri.Ups, ri.Active
	}
	type vrow struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Proto  string `json:"proto"`
		Ping   int    `json:"ping"`
		KBps   int    `json:"kbps"`
		Source string `json:"source"`
		InPool bool   `json:"inPool"`
	}
	pcRouterMu.Lock()
	inPool := map[string]bool{}
	for _, sl := range pcPool {
		inPool[sl.Server.ID] = true
	}
	pcRouterMu.Unlock()
	var vl []vrow
	for i, r := range vpnBest(&s, isTG) {
		if i >= 12 {
			break
		}
		p := r.Ping
		if isTG {
			p = r.TG
		}
		vl = append(vl, vrow{r.ID, r.Name, r.Proto, p, r.KBps, r.Source, inPool[r.ID]})
	}
	found, _ := tgFoundList()
	return map[string]any{"route": s.Routes[svc], "active": active, "ups": ups, "vpn": vl, "vpnAvailable": runMode == modeNoVPN,
		"tg": isTG, "tgProxies": len(tgUpstreams()) + len(found), "tgLink": tgCurrentLink}
}

// setRoute - способ для сервиса вручную ("" - автоматически)
func setRoute(svc, v string) {
	// выбран способ - None для сервиса больше не действует (pinStrategy снимает и выбор способа - поэтому раньше)
	if cfg := loadConfig(); v != "" && cfg != nil && cfg.Pins[svc] == NoneID {
		pinStrategy(svc, "")
	}
	vpnUpdate(func(s *vpnState) {
		if s.Routes == nil {
			s.Routes = map[string]string{}
		}
		if v == "" {
			delete(s.Routes, svc)
		} else {
			s.Routes[svc] = v
		}
	})
	switch {
	case v == "":
		info("%s: способ - автоматически", svc)
	case strings.HasPrefix(v, "vpn"):
		info("%s: через VPN, остальные способы - запасные", svc)
	case v == "tg-ws":
		info("%s: через WebSocket, остальные способы - запасные", svc)
	case v == "tg-proxy":
		info("%s: через MTProto-прокси, остальные способы - запасные", svc)
	default:
		info("%s: через обход, остальные способы - запасные", svc)
	}
	if svc != "Telegram" {
		pcRefreshVPN(true)
	}
}
