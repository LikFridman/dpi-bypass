//go:build windows

package main

// Технические отчёты для разработчика (см. AGREEMENT.md): отправляются при каждом
// подключении и при ошибках на Cloudflare Worker разработчика (адрес - report_url
// в update/update.json). Без согласия с соглашением обход не включается.

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const agreementVersion = 1

//go:embed AGREEMENT.md
var agreementText string

// ---------- согласие ----------

func consentOK() bool { return settings.Consent >= agreementVersion || uitestMode }

func setConsent(ok bool) {
	if ok {
		settings.Consent = agreementVersion
		settings.ConsentAt = time.Now().Format(time.RFC3339)
	} else {
		settings.Consent = 0
	}
	saveSettings()
}

// askConsentConsole - согласие в терминале (консольный режим)
func askConsentConsole() bool {
	if consentOK() {
		return true
	}
	title("Пользовательское соглашение")
	for _, l := range strings.Split(agreementText, "\n") {
		say("  %s", strings.TrimLeft(l, "# "))
	}
	if askYes("Принимаешь соглашение? Без него обход не включится") {
		setConsent(true)
		return true
	}
	return false
}

// ---------- сбор данных ----------

type tmSite struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Ping   int    `json:"ping_ms,omitempty"`
	Stage  string `json:"stage,omitempty"`
	Reason string `json:"reason,omitempty"`
	DNSBad bool   `json:"dns_bad,omitempty"`
}

type tmStrategy struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Opens    []string `json:"opens"`
	Fails    []string `json:"fails"`
	StartErr string   `json:"start_error,omitempty"`
}

var (
	tmMu       sync.Mutex
	tmBaseline []tmSite
	tmTested   []tmStrategy
	tmErrors   []string
	tmLastErr  time.Time
)

var stageNames = map[Stage]string{StOK: "", StDNS: "dns", StTCP: "tcp", StTLS: "tls", StData: "data", StThrottle: "throttle"}

func tmSites(res map[string]SvcResult) []tmSite {
	var out []tmSite
	for name, r := range res {
		out = append(out, tmSite{Name: name, OK: r.OK, Ping: r.Ms, Stage: stageNames[r.Stage], Reason: r.Reason, DNSBad: r.DNSBad})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func tmSetBaseline(res map[string]SvcResult) {
	tmMu.Lock()
	tmBaseline = tmSites(res)
	tmTested = nil
	tmMu.Unlock()
}

func tmRecordStrategy(st Strategy, cands []Service, works map[string]bool, startErr error) {
	t := tmStrategy{ID: st.ID, Name: st.Name, Opens: []string{}, Fails: []string{}}
	if startErr != nil {
		t.StartErr = shortText(startErr.Error(), 300)
	}
	for _, s := range cands {
		if works[s.Name] {
			t.Opens = append(t.Opens, s.Name)
		} else if startErr == nil {
			t.Fails = append(t.Fails, s.Name)
		}
	}
	tmMu.Lock()
	tmTested = append(tmTested, t)
	tmMu.Unlock()
}

// tmError запоминает ошибку и отправляет отчёт (не чаще раза в 10 минут)
func tmError(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	tmMu.Lock()
	tmErrors = append(tmErrors, time.Now().Format("15:04:05")+" "+msg)
	if len(tmErrors) > 30 {
		tmErrors = tmErrors[len(tmErrors)-30:]
	}
	send := time.Since(tmLastErr) > 10*time.Minute
	if send {
		tmLastErr = time.Now()
	}
	tmMu.Unlock()
	if send {
		sendReport("error")
	}
}

func shortText(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ---------- обезличивание журнала ----------

var ansiStrip = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func sanitizer() *strings.Replacer {
	var pairs []string
	add := func(v, repl string) {
		v = strings.TrimSpace(v)
		if len(v) < 3 {
			return
		}
		pairs = append(pairs, v, repl, strings.ToLower(v), repl, strings.ToUpper(v), repl)
	}
	add(baseDir, "<папка программы>")
	add(os.Getenv("USERPROFILE"), "<папка пользователя>")
	add(os.Getenv("COMPUTERNAME"), "<компьютер>")
	add(os.Getenv("USERNAME"), "<пользователь>")
	return strings.NewReplacer(pairs...)
}

func tmLogTail(n int) []string {
	uiMu.Lock()
	h := append([]string{}, uiHistory...)
	uiMu.Unlock()
	if len(h) == 0 { // консольный режим - берём из файла журнала
		if b, err := os.ReadFile(logPath); err == nil {
			if len(b) > 256<<10 {
				b = b[len(b)-256<<10:]
			}
			h = strings.Split(string(b), "\n")
		}
	}
	if len(h) > n {
		h = h[len(h)-n:]
	}
	r := sanitizer()
	out := make([]string, 0, len(h))
	for _, l := range h {
		l = strings.TrimRight(ansiStrip.ReplaceAllString(l, ""), "\r ")
		if l != "" {
			out = append(out, shortText(r.Replace(l), 400))
		}
	}
	return out
}

// ---------- отчёт ----------

func buildReport(trigger string) map[string]any {
	isp := currentISP()
	engCfgMu.Lock()
	cfg, res := engCfg, engRes
	engCfgMu.Unlock()
	if cfg == nil {
		cfg = loadConfigCached()
	}
	tmMu.Lock()
	baseline := append([]tmSite{}, tmBaseline...)
	tested := append([]tmStrategy{}, tmTested...)
	errs := append([]string{}, tmErrors...)
	tmMu.Unlock()

	mode := map[int]string{modeNoVPN: "no_vpn", modeWithVPN: "with_vpn"}[runMode]
	rep := map[string]any{
		"schema":  1,
		"trigger": trigger,
		"time":    time.Now().Format(time.RFC3339),
		"app":     map[string]any{"platform": "windows", "version": version, "mode": mode, "running": engRunning.Load(), "gui": guiMode},
		"device": map[string]any{
			"os": "Windows", "build": windowsBuild(), "arch": runtime.GOARCH, "admin": isAdmin(),
			"webview2": webUIActive, "missing_files": missingZapretFiles(),
		},
		"network": map[string]any{
			"ip": isp.IP, "asn": isp.ASN, "isp": isp.Name, "city": isp.City, "country": isp.Country,
		},
		"vpn": map[string]any{
			"detected": curVPN.Active(), "clients": curVPN.Procs, "adapters": curVPN.TunNames,
			"full_tunnel": curVPN.FullTunnel, "mode": curVPN.Mode(), "system_proxy": curVPN.SysProxy,
			"servers": curVPN.ServerIPs, "socks": curVPN.Socks,
		},
		"baseline": baseline,
		"tested":   tested,
		"errors":   errs,
		"log":      tmLogTail(200),
	}
	if res != nil {
		rep["sites"] = tmSites(res)
	}
	if cfg != nil {
		var groups []map[string]any
		for _, g := range cfg.Groups {
			st, _ := strategyByID(g.Strategy)
			groups = append(groups, map[string]any{"id": g.Strategy, "name": st.Name, "sites": g.Services})
		}
		rep["strategy"] = map[string]any{
			"groups": groups, "custom_sites": cfg.Sites, "unfixable": cfg.Unfixable,
			"expected": cfg.Expected, "dns_bad": cfg.DNSBad, "selected": cfg.Created.Format(time.RFC3339),
		}
	}
	tgInfo := map[string]any{"running": tgProxy != nil, "worker": tgWorkerHost != "", "backup_proxies": tgUpstreamNames()}
	if tgProxy != nil {
		a, t, ws, tcp, f := tgProxy.Stats()
		tgInfo["connections"] = map[string]int64{"active": a, "total": t, "websocket": ws, "tcp": tcp, "failed": f}
		tgInfo["routes"] = tgProxy.RouteStats()
	}
	rep["telegram"] = tgInfo
	return rep
}

// ---------- отправка ----------

func reportQueueDir() string { return filepath.Join(dataDir, "reports") }

// reportURL - адрес Worker'а для отчётов: report_url из update.json (или файл report-url.txt)
func reportURL() string {
	if b, err := os.ReadFile(filepath.Join(dataDir, "report-url.txt")); err == nil {
		if u := strings.TrimSpace(string(b)); strings.HasPrefix(u, "https://") {
			return strings.TrimRight(u, "/")
		}
	}
	if b, err := os.ReadFile(updateCache()); err == nil {
		var ru struct {
			ReportURL string `json:"report_url"`
		}
		if json.Unmarshal(b, &ru) == nil && strings.HasPrefix(ru.ReportURL, "https://") {
			return strings.TrimRight(ru.ReportURL, "/")
		}
	}
	return ""
}

var reportMu sync.Mutex

// sendReport собирает отчёт, кладёт его в очередь и пытается отправить всё, что накопилось
func sendReport(trigger string) {
	if !consentOK() || uitestMode {
		return
	}
	rep := buildReport(trigger)
	b, err := json.Marshal(rep)
	if err != nil {
		return
	}
	os.MkdirAll(reportQueueDir(), 0755)
	rnd := make([]byte, 3)
	rand.Read(rnd)
	name := fmt.Sprintf("%d-%s.json", time.Now().UnixMilli(), hex.EncodeToString(rnd))
	os.WriteFile(filepath.Join(reportQueueDir(), name), b, 0644)
	go flushReports(trigger == "manual")
}

func flushReports(verbose bool) {
	reportMu.Lock()
	defer reportMu.Unlock()
	files, _ := filepath.Glob(filepath.Join(reportQueueDir(), "*.json"))
	sort.Strings(files)
	if len(files) > 20 { // хранить не больше 20 неотправленных
		for _, f := range files[:len(files)-20] {
			os.Remove(f)
		}
		files = files[len(files)-20:]
	}
	u := reportURL()
	if u == "" {
		if verbose {
			uiToast("Отчёт сохранён, но адрес для отчётов ещё не настроен разработчиком.")
		}
		return
	}
	cl := &http.Client{Timeout: 15 * time.Second}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		resp, err := cl.Post(u+"/report", "application/json", bytes.NewReader(b))
		if err != nil {
			if verbose {
				uiToast("Отчёт не отправился (" + shortErr(err) + "), попробую позже.")
			}
			return
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			os.Remove(f)
			var r struct{ ID string }
			json.Unmarshal(body, &r)
			info("Отчёт для разработчика отправлен, номер %s", r.ID)
			if verbose {
				uiToast("Отчёт отправлен, номер " + r.ID)
			}
		} else if resp.StatusCode == 400 || resp.StatusCode == 413 {
			os.Remove(f) // сервер такой отчёт не примет никогда
		} else {
			return // 429/5xx - позже
		}
	}
}
