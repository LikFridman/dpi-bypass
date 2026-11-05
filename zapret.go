//go:build windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// основной адрес и зеркало (raw.githubusercontent.com у некоторых провайдеров заблокирован)
var zapretBases = []string{
	"https://raw.githubusercontent.com/bol-van/zapret-win-bundle/master/zapret-winws/",
	"https://cdn.jsdelivr.net/gh/bol-van/zapret-win-bundle@master/zapret-winws/",
}

var zapretFiles = []string{
	"winws.exe",
	"WinDivert.dll",
	"WinDivert64.sys",
	"cygwin1.dll",
	"files/quic_initial_www_google_com.bin",
	"files/list-youtube.txt",
	"windivert.filter/windivert_part.quic_initial_ietf.txt",
	"windivert.filter/windivert_part.discord_media.txt",
	"windivert.filter/windivert_part.stun.txt",
}

func zp(rel string) string { return filepath.Join(zapDir, filepath.FromSlash(rel)) }

func missingZapretFiles() []string {
	var miss []string
	for _, f := range zapretFiles {
		if _, err := os.Stat(zp(f)); err != nil {
			miss = append(miss, f)
		}
	}
	return miss
}

// ensureZapret находит или скачивает winws и драйвер WinDivert.
func ensureZapret() error {
	// если рядом с exe уже лежит папка zapret-winws - используем её
	if local := filepath.Join(baseDir, "zapret-winws"); fileExists(filepath.Join(local, "winws.exe")) {
		zapDir = local
	}
	miss := missingZapretFiles()
	if len(miss) == 0 {
		return nil
	}
	title("Загрузка winws (zapret)")
	info("Источник: github.com/bol-van/zapret-win-bundle")
	cl := &http.Client{Timeout: 90 * time.Second}
	for _, f := range miss {
		fmt.Fprintf(out, "    %s ... ", f)
		var err error
		for _, base := range zapretBases {
			if err = download(cl, base+f, zp(f)); err == nil {
				break
			}
		}
		if err != nil {
			say(col(cRed, "ошибка"))
			return fmt.Errorf("не удалось скачать %s: %v", f, err)
		}
		say(col(cGreen, "ok"))
	}
	if miss := missingZapretFiles(); len(miss) > 0 {
		return fmt.Errorf("файлы пропали сразу после загрузки (%s) - скорее всего их удалил антивирус", strings.Join(miss, ", "))
	}
	return nil
}

func download(cl *http.Client, url, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	resp, err := cl.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp := dst + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	os.Remove(dst)
	return os.Rename(tmp, dst)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// ---------- стратегии ----------

var strategies = []Strategy{
	{"s1", "fake + multidisorder, md5sig, подмена SNI", []string{"--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-repeats=11", "--dpi-desync-fooling=md5sig", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com"}},
	{"s2", "fake + multidisorder, badseq+md5sig", []string{"--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=midsld", "--dpi-desync-repeats=6", "--dpi-desync-fooling=badseq,md5sig"}},
	{"s3", "fake + multisplit, badseq, случайный SNI", []string{"--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-repeats=6", "--dpi-desync-fooling=badseq", "--dpi-desync-fake-tls-mod=rnd,rndsni"}},
	{"s4", "fake + fakedsplit, autottl", []string{"--dpi-desync=fake,fakedsplit", "--dpi-desync-split-pos=1", "--dpi-desync-autottl=2", "--dpi-desync-fooling=md5sig"}},
	{"s5", "multisplit + seqovl", []string{"--dpi-desync=multisplit", "--dpi-desync-split-pos=1", "--dpi-desync-split-seqovl=568"}},
	{"s6", "fake + multidisorder, datanoack", []string{"--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=midsld", "--dpi-desync-repeats=6", "--dpi-desync-fooling=datanoack"}},
	{"s7", "fakeddisorder, badseq", []string{"--dpi-desync=fakeddisorder", "--dpi-desync-split-pos=midsld", "--dpi-desync-repeats=6", "--dpi-desync-fooling=badseq"}},
	{"s8", "fake + multisplit по sniext, autottl", []string{"--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=1,sniext+1", "--dpi-desync-autottl=2", "--dpi-desync-repeats=6", "--dpi-desync-fooling=md5sig"}},
	{"s9", "multidisorder без фейков", []string{"--dpi-desync=multidisorder", "--dpi-desync-split-pos=1,midsld"}},
	{"s10", "syndata + multisplit", []string{"--dpi-desync=syndata,multisplit", "--dpi-desync-split-pos=1,midsld"}},
	{"s11", "hostfakesplit, badseq", []string{"--dpi-desync=hostfakesplit", "--dpi-desync-fooling=badseq", "--dpi-desync-repeats=4"}},
	{"s12", "fake + multisplit, ts", []string{"--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=midsld", "--dpi-desync-repeats=8", "--dpi-desync-fooling=ts", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com"}},
}

func strategyByID(id string) (Strategy, bool) {
	for _, s := range strategies {
		if s.ID == id {
			return s, true
		}
	}
	return Strategy{}, false
}

// curVPN - текущее состояние VPN (обновляется сторожем)
var curVPN VPNState

func exclArgs() []string {
	if f := writeVPNExclude(curVPN); f != "" {
		return []string{"--ipset-exclude=" + f}
	}
	return nil
}

func testArgs(s Strategy) []string {
	args := append(ifaceArg(curVPN), "--wf-tcp=443", "--filter-tcp=443")
	args = append(args, exclArgs()...)
	return append(args, s.Args...)
}

// buildArgs собирает итоговую конфигурацию winws из нескольких профилей.
func buildArgs(cfg *Config, svcs []Service, withUDPExtras bool) ([]string, error) {
	listDir := filepath.Join(dataDir, "lists")
	os.MkdirAll(listDir, 0755)
	byName := map[string]Service{}
	for _, s := range svcs {
		byName[s.Name] = s
	}

	ex := exclArgs()
	args := append(ifaceArg(curVPN), "--wf-tcp=80,443", "--wf-raw-part=@"+zp("windivert.filter/windivert_part.quic_initial_ietf.txt"))
	if withUDPExtras {
		args = append(args,
			"--wf-raw-part=@"+zp("windivert.filter/windivert_part.discord_media.txt"),
			"--wf-raw-part=@"+zp("windivert.filter/windivert_part.stun.txt"))
	}
	// HTTP (порт 80)
	args = append(args, "--filter-tcp=80")
	args = append(args, ex...)
	args = append(args, "--dpi-desync=fake,fakedsplit", "--dpi-desync-autottl=2", "--dpi-desync-fooling=md5sig", "--new")

	// профили под конкретные сервисы
	for i, g := range cfg.Groups {
		st, ok := strategyByID(g.Strategy)
		if !ok {
			continue
		}
		var doms []string
		for _, n := range g.Services {
			doms = append(doms, byName[n].Domains...)
		}
		if len(doms) == 0 {
			continue
		}
		lf := filepath.Join(listDir, fmt.Sprintf("group%d.txt", i+1))
		if err := os.WriteFile(lf, []byte(strings.Join(doms, "\n")+"\n"), 0644); err != nil {
			return nil, err
		}
		args = append(args, "--filter-tcp=443", "--hostlist="+lf)
		args = append(args, ex...)
		args = append(args, st.Args...)
		args = append(args, "--new")
	}

	// универсальный профиль: сайты не из списка, которые начнут отваливаться, добавятся сами
	best, ok := strategyByID(cfg.Best)
	if !ok {
		best = strategies[0]
	}
	// свой Cloudflare Worker для Telegram тоже пропускаем через обход
	if tgWorkerHost != "" {
		args = append(args, "--filter-tcp=443", "--hostlist-domains="+tgWorkerHost)
		args = append(args, ex...)
		args = append(args, best.Args...)
		args = append(args, "--new")
	}

	auto := filepath.Join(listDir, "auto-hostlist.txt")
	if !fileExists(auto) {
		os.WriteFile(auto, nil, 0644)
	}
	args = append(args, "--filter-tcp=443", "--hostlist-auto="+auto, "--hostlist-auto-fail-threshold=2")
	args = append(args, ex...)
	args = append(args, best.Args...)
	args = append(args, "--new")

	// QUIC (HTTP/3)
	args = append(args, "--filter-l7=quic", "--hostlist="+zp("files/list-youtube.txt"))
	args = append(args, ex...)
	args = append(args, "--dpi-desync=fake", "--dpi-desync-repeats=11", "--dpi-desync-fake-quic="+zp("files/quic_initial_www_google_com.bin"), "--new",
		"--filter-l7=quic")
	args = append(args, ex...)
	args = append(args, "--dpi-desync=fake", "--dpi-desync-repeats=11")
	if withUDPExtras {
		// голос Discord и STUN
		args = append(args, "--new", "--filter-l7=discord,stun")
		args = append(args, ex...)
		args = append(args, "--dpi-desync=fake", "--dpi-desync-repeats=6")
	}
	return args, nil
}

// ---------- процесс winws ----------

type ringBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (r *ringBuf) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.b.Write(p)
	if r.b.Len() > 8192 {
		tail := append([]byte(nil), r.b.Bytes()[r.b.Len()-4096:]...)
		r.b.Reset()
		r.b.Write(tail)
	}
	return len(p), nil
}

func (r *ringBuf) Tail() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	lines := strings.Split(strings.TrimSpace(r.b.String()), "\n")
	if len(lines) > 6 {
		lines = lines[len(lines)-6:]
	}
	return strings.Join(lines, "\n")
}

type Winws struct {
	cmd  *exec.Cmd
	out  *ringBuf
	done chan struct{}
}

var (
	activeMu sync.Mutex
	active   *Winws
)

func startWinws(args []string) (*Winws, error) {
	if len(curVPN.TunNames) > 0 && curVPN.PhysIdx == 0 {
		// без привязки к настоящему адаптеру winws полез бы внутрь VPN-туннеля и сломал его
		return nil, fmt.Errorf("включён VPN-туннель, а физический адаптер не найден - обход не запускаю, чтобы не сломать VPN")
	}
	w := &Winws{out: &ringBuf{}, done: make(chan struct{})}
	w.cmd = exec.Command(zp("winws.exe"), args...)
	w.cmd.Dir = zapDir
	w.cmd.Stdout, w.cmd.Stderr = w.out, w.out
	w.cmd.SysProcAttr = hiddenProcAttr()
	if err := w.cmd.Start(); err != nil {
		return nil, err
	}
	attachToJob(w.cmd.Process.Pid)
	go func() { w.cmd.Wait(); close(w.done) }()

	select {
	case <-w.done:
		msg := w.out.Tail()
		if msg == "" {
			msg = "без сообщения"
		}
		explainWinwsExit(msg)
		return nil, fmt.Errorf("winws сразу завершился: %s", msg)
	case <-time.After(1500 * time.Millisecond):
	}
	activeMu.Lock()
	active = w
	activeMu.Unlock()
	return w, nil
}

func (w *Winws) Alive() bool {
	select {
	case <-w.done:
		return false
	default:
		return true
	}
}

func (w *Winws) Stop() {
	if w == nil {
		return
	}
	if w.Alive() {
		w.cmd.Process.Kill()
		select {
		case <-w.done:
		case <-time.After(3 * time.Second):
		}
	}
	activeMu.Lock()
	if active == w {
		active = nil
	}
	activeMu.Unlock()
	time.Sleep(300 * time.Millisecond) // дать драйверу отпустить фильтр
}

func stopActive() {
	activeMu.Lock()
	w := active
	activeMu.Unlock()
	w.Stop()
}

// ---------- сторонние процессы ----------

func runningProcesses() map[string]bool {
	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	res := map[string]bool{}
	if err != nil {
		return res
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.SplitN(line, ",", 2)
		if len(f) > 0 {
			res[strings.ToLower(strings.Trim(strings.TrimSpace(f[0]), `"`))] = true
		}
	}
	return res
}

func killStrayWinws() bool {
	if !runningProcesses()["winws.exe"] {
		return false
	}
	c := exec.Command("taskkill", "/F", "/IM", "winws.exe")
	c.SysProcAttr = hiddenProcAttr()
	c.Run()
	time.Sleep(500 * time.Millisecond)
	return true
}

func checkConflicts() {
	p := runningProcesses()
	for _, name := range []string{"goodbyedpi.exe", "byedpi.exe", "ciadpi.exe"} {
		if p[name] {
			warn("Запущен %s - он конфликтует с обходом. Закрой его, иначе результаты будут неверными.", name)
		}
	}
	if svcs := conflictingServices(); len(svcs) > 0 {
		warn("Работает служба другого обхода: %s - вместе они мешают друг другу.", strings.Join(svcs, ", "))
		if askYes("Остановить её (до перезагрузки)?") {
			stopServices(svcs)
			time.Sleep(time.Second)
		}
	}
	if killStrayWinws() {
		info("Остановил ранее запущенный winws.exe")
	}
}
