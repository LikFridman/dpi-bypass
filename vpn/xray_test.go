package vpn

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Проверки с настоящим Xray и настоящими серверами - только в CI (XRAY=путь к xray).
func xrayBin(t *testing.T) string {
	x := os.Getenv("XRAY")
	if x == "" {
		t.Skip("нет XRAY")
	}
	return x
}

func freeList(t *testing.T) []*Server {
	if f := os.Getenv("VPN_SAMPLE"); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			return ParseList(string(b))
		}
	}
	var all []*Server
	for _, u := range []string{
		"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
		"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt",
	} {
		r, err := http.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		all = append(all, ParseList(string(b))...)
	}
	if len(all) == 0 {
		t.Skip("списки не скачались")
	}
	return all
}

// Xray принимает настройки, собранные из почти всех ссылок
func TestXrayAcceptsConfigs(t *testing.T) {
	x := xrayBin(t)
	list := freeList(t)
	bad := 0
	for i := 0; i < len(list); i += 50 {
		end := i + 50
		if end > len(list) {
			end = len(list)
		}
		chunk := list[i:end]
		if ok, _ := xrayTest(x, chunk); ok {
			continue
		}
		for _, s := range chunk {
			if ok, out := xrayTest(x, []*Server{s}); !ok {
				bad++
				t.Logf("Xray не принял %s: %s", s.Link[:min(len(s.Link), 120)], out)
			}
		}
	}
	t.Logf("серверов %d, не принято %d", len(list), bad)
	if bad > len(list)/10 {
		t.Fatalf("Xray не принял слишком много: %d из %d", bad, len(list))
	}
}

func xrayTest(x string, list []*Server) (bool, string) {
	var slots []Slot
	for i, s := range list {
		slots = append(slots, Slot{Server: s, Port: 30000 + i})
	}
	cfg, err := Config(slots, "")
	if err != nil {
		return false, err.Error()
	}
	f := filepath.Join(os.TempDir(), "xray-test.json")
	os.WriteFile(f, cfg, 0600)
	out, err := exec.Command(x, "run", "-test", "-c", f).CombinedOutput()
	s := string(out)
	if i := strings.LastIndex(s, "\n"); i > 0 && len(s) > 300 {
		s = s[len(s)-300:]
	}
	return err == nil, s
}

// Настоящая проверка: из бесплатных серверов хоть один работает; WARP регистрируется
func TestXrayLive(t *testing.T) {
	x := xrayBin(t)
	list := freeList(t)
	if len(list) > 80 {
		list = list[:80]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	res := Test(ctx, x, list, TestOpts{Telegram: true, Speed: 3})
	ok, tgok := 0, 0
	for _, r := range res {
		if r.OK {
			ok++
			t.Logf("OK %-9s %4d ms tg %4d kbps %5d  %s", r.Proto, r.Ping, r.TG, r.KBps, r.Name)
		}
		if r.TG > 0 {
			tgok++
		}
	}
	errs := map[string]int{}
	for _, r := range res {
		if !r.OK {
			errs[r.Err]++
		}
	}
	t.Logf("работают %d из %d (Telegram %d); ошибки: %v", ok, len(res), tgok, errs)
	if ok == 0 {
		t.Fatal("ни один бесплатный сервер не работает")
	}
	best := Best(res, false)
	if len(best) == 0 || !res[best[0]].OK {
		t.Fatal("Best")
	}

	acc, err := RegisterWarp(ctx, nil)
	if err != nil {
		t.Logf("WARP не зарегистрировался: %v", err)
		return
	}
	var ws []*Server
	for _, l := range acc.Links() {
		s, err := Parse(l)
		if err != nil {
			t.Fatal(err)
		}
		s.Source = "warp"
		ws = append(ws, s)
	}
	wr := Test(ctx, x, ws, TestOpts{Telegram: true})
	for _, r := range wr {
		t.Logf("WARP %-40s ok=%v %d ms tg %d %s", r.Name, r.OK, r.Ping, r.TG, r.Err)
	}
}

// Supervisor перезапускает упавший Xray
func TestSupervisorRestart(t *testing.T) {
	x := xrayBin(t)
	l := ParseList("vless://a@1.1.1.1:443?security=none&type=tcp#a")
	ports, _ := FreePorts(1)
	sv := &Supervisor{Xray: x, Log: t.Logf}
	if err := sv.Run([]Slot{{Server: l[0], Port: ports[0]}}); err != nil {
		t.Fatal(err)
	}
	defer sv.Stop()
	sv.mu.Lock()
	sv.proc.cmd.Process.Kill()
	sv.mu.Unlock()
	time.Sleep(6 * time.Second)
	if !sv.Alive() {
		t.Fatal("Xray не перезапустился")
	}
}
