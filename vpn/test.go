package vpn

import (
	"context"
	"crypto/tls"
	"dpibypass/tg"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Result - итог проверки сервера
type Result struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Ping   int    `json:"ping"`             // мс, запрос к сайту через сервер
	TG     int    `json:"tg,omitempty"`     // мс, ответ Telegram (DC2) через сервер; 0 - не проверялось или нет
	KBps   int    `json:"kbps,omitempty"`   // скорость скачивания, КБ/с
	Err    string `json:"err,omitempty"`    // почему не работает
	Name   string `json:"name,omitempty"`   //
	Proto  string `json:"proto,omitempty"`  //
	Source string `json:"source,omitempty"` //
	Link   string `json:"link,omitempty"`   // исходная ссылка (для приложения)
}

// TestOpts - что проверять
type TestOpts struct {
	Telegram bool          // проверить Telegram через сервер
	Speed    int           // замерить скорость у стольких лучших (0 - не мерить)
	Timeout  time.Duration // на один сервер (по умолчанию 8 с)
	Parallel int           // одновременно (по умолчанию 24)
	Setup    func(*exec.Cmd)
	Log      func(format string, a ...any)
}

// Probe проверяет сервис через SOCKS5 на addr: время ответа сайта (мс).
func Probe(socks string, timeout time.Duration) (int, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tg.SocksDial(socks, addr)
		},
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
		TLSClientConfig:     &tls.Config{},
	}
	cl := &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	best := 0
	var last error
	for _, u := range []string{"https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"} {
		t := time.Now()
		r, err := cl.Get(u)
		if err != nil {
			last = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
		r.Body.Close()
		if r.StatusCode != 204 && r.StatusCode != 200 {
			last = fmt.Errorf("HTTP %d", r.StatusCode)
			continue
		}
		ms := int(time.Since(t).Milliseconds())
		if ms < 1 {
			ms = 1
		}
		if best == 0 || ms < best {
			best = ms
		}
	}
	if best == 0 {
		return 0, shortErr(last)
	}
	return best, nil
}

// ProbeTG - ответ Telegram (DC2, настоящий MTProto) через SOCKS5, мс
func ProbeTG(socks string, timeout time.Duration) (int, error) {
	d, err := tg.CheckDC(func(addr string) (net.Conn, error) { return tg.SocksDial(socks, addr) }, 2, timeout)
	if err != nil {
		return 0, shortErr(err)
	}
	ms := int(d.Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

// Speed - скорость скачивания через SOCKS5, КБ/с (до 6 с или 4 МБ)
func Speed(socks string) int {
	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return tg.SocksDial(socks, addr)
	}, DisableKeepAlives: true}
	cl := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	t := time.Now()
	r, err := cl.Get("https://speed.cloudflare.com/__down?bytes=4000000")
	if err != nil {
		return 0
	}
	defer r.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(&timedReader{r.Body, t.Add(6 * time.Second)}, 4000000))
	d := time.Since(t).Seconds()
	if d <= 0 || n < 64<<10 {
		return 0
	}
	return int(float64(n) / 1024 / d)
}

type timedReader struct {
	r  io.Reader
	at time.Time
}

func (t *timedReader) Read(b []byte) (int, error) {
	if time.Now().After(t.at) {
		return 0, io.EOF
	}
	return t.r.Read(b)
}

func shortErr(err error) error {
	if err == nil {
		return fmt.Errorf("нет ответа")
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "deadline exceeded"), strings.Contains(s, "timeout"), strings.Contains(s, "Timeout"):
		return fmt.Errorf("нет ответа")
	case strings.Contains(s, "connection refused"):
		return fmt.Errorf("отказ")
	case strings.Contains(s, "reset"):
		return fmt.Errorf("сброс соединения")
	case strings.Contains(s, "EOF"):
		return fmt.Errorf("соединение закрыто")
	}
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		s = s[i+2:]
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return fmt.Errorf("%s", s)
}

// startSome запускает Xray с теми серверами из списка, чьи настройки он принимает: если один
// сервер ломает все настройки (Xray не стартует), список делится пополам, пока не найдутся плохие.
func startSome(xray string, list []*Server, setup func(*exec.Cmd), bad map[string]string) (*Proc, []Slot) {
	if len(list) == 0 {
		return nil, nil
	}
	ports, err := FreePorts(len(list))
	if err != nil {
		return nil, nil
	}
	slots := make([]Slot, len(list))
	for i, s := range list {
		slots[i] = Slot{Server: s, Port: ports[i]}
	}
	cfg, err := Config(slots, "")
	if err == nil {
		p, err := Start(xray, cfg, ports, setup)
		if err == nil {
			return p, slots
		}
		if len(list) == 1 {
			bad[list[0].ID] = "Xray не принял настройки: " + trimTail(err.Error())
			return nil, nil
		}
	}
	if len(list) == 1 {
		return nil, nil
	}
	// делим пополам; запускаем оба куска по отдельности и сливаем в один список - но это два
	// процесса: проще вернуть первый рабочий, а второй проверить следующим заходом
	h := len(list) / 2
	p1, s1 := startSome(xray, list[:h], setup, bad)
	if p1 != nil {
		p1.Stop()
	}
	p2, s2 := startSome(xray, list[h:], setup, bad)
	if p2 != nil {
		p2.Stop()
	}
	var good []*Server
	for _, s := range append(s1, s2...) {
		good = append(good, s.Server)
	}
	if len(good) == 0 {
		return nil, nil
	}
	ports, err = FreePorts(len(good))
	if err != nil {
		return nil, nil
	}
	slots = make([]Slot, len(good))
	for i, s := range good {
		slots[i] = Slot{Server: s, Port: ports[i]}
	}
	cfg, _ = Config(slots, "")
	p, err := Start(xray, cfg, ports, setup)
	if err != nil {
		return nil, nil
	}
	return p, slots
}

func trimTail(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// Test проверяет серверы (партиями по 40 на один Xray) и возвращает итоги в том же порядке.
func Test(ctx context.Context, xray string, list []*Server, o TestOpts) []Result {
	if o.Timeout == 0 {
		o.Timeout = 8 * time.Second
	}
	if o.Parallel == 0 {
		o.Parallel = 24
	}
	res := make([]Result, len(list))
	if _, err := os.Stat(xray); err != nil {
		for i, s := range list {
			res[i] = Result{ID: s.ID, Name: s.Label(), Proto: s.Proto, Source: s.Source, Err: "нет Xray"}
		}
		return res
	}
	idx := map[string]int{}
	for i, s := range list {
		res[i] = Result{ID: s.ID, Name: s.Label(), Proto: s.Proto, Source: s.Source, Err: "не проверен"}
		idx[s.ID] = i
	}
	bad := map[string]string{}
	for start := 0; start < len(list); start += 40 {
		if ctx.Err() != nil {
			break
		}
		end := start + 40
		if end > len(list) {
			end = len(list)
		}
		p, slots := startSome(xray, list[start:end], o.Setup, bad)
		if p == nil {
			for _, s := range list[start:end] {
				if e, ok := bad[s.ID]; ok {
					res[idx[s.ID]].Err = e
				} else {
					res[idx[s.ID]].Err = "Xray не запустился"
				}
			}
			continue
		}
		var wg sync.WaitGroup
		sem := make(chan struct{}, o.Parallel)
		for _, sl := range slots {
			wg.Add(1)
			sem <- struct{}{}
			go func(sl Slot) {
				defer wg.Done()
				defer func() { <-sem }()
				i := idx[sl.Server.ID]
				addr := fmt.Sprintf("127.0.0.1:%d", sl.Port)
				ms, err := Probe(addr, o.Timeout)
				if err != nil {
					res[i].Err = err.Error()
				} else {
					res[i].OK, res[i].Ping, res[i].Err = true, ms, ""
				}
				if o.Telegram && (err == nil || sl.Server.Source == "own") {
					if t, err := ProbeTG(addr, o.Timeout); err == nil {
						res[i].TG = t
					}
				}
			}(sl)
		}
		wg.Wait()
		if o.Speed > 0 {
			var ok []Slot
			for _, sl := range slots {
				if res[idx[sl.Server.ID]].OK {
					ok = append(ok, sl)
				}
			}
			sort.Slice(ok, func(a, b int) bool { return res[idx[ok[a].Server.ID]].Ping < res[idx[ok[b].Server.ID]].Ping })
			if len(ok) > o.Speed {
				ok = ok[:o.Speed]
			}
			for _, sl := range ok {
				res[idx[sl.Server.ID]].KBps = Speed(fmt.Sprintf("127.0.0.1:%d", sl.Port))
			}
		}
		p.Stop()
		for _, s := range list[start:end] {
			if e, ok := bad[s.ID]; ok {
				res[idx[s.ID]].Err = e
			}
		}
	}
	return res
}

// Best - номера работающих серверов, лучшие первыми (свои - выше бесплатных при близком пинге).
// forTG - для Telegram важен ответ Telegram, а не сайта.
func Best(res []Result, forTG bool) []int {
	var out []int
	for i, r := range res {
		if !r.OK || (forTG && r.TG == 0) {
			continue
		}
		out = append(out, i)
	}
	score := func(r Result) float64 {
		v := float64(r.Ping)
		if forTG {
			v = float64(r.TG)
		}
		if r.KBps > 0 && r.KBps < 300 {
			v += 400 // медленный
		}
		if r.Source == "own" {
			v *= 0.6
		}
		return v
	}
	sort.SliceStable(out, func(a, b int) bool { return score(res[out[a]]) < score(res[out[b]]) })
	return out
}
