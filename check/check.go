// Package check - проверка сервисов «по-настоящему»: не просто ответил ли сайт,
// а тянутся ли данные. ТСПУ часто пропускают начало соединения и рвут его после
// ~16 КБ, поэтому сайт может «открываться», а видео, картинки и файлы - нет.
//
// Для каждого сервиса:
//   - ping: время TCP-соединения;
//   - страница: TLS + HTTP, тело до 512 КБ;
//   - нагрузка: файл с CDN этого сервиса (скрипт/картинка со страницы), для YouTube -
//     настоящее видео с googlevideo, для Discord - ещё и WebSocket-шлюз,
//     для Telegram - запрос MTProto к серверу DC;
//   - стадия обрыва: dns / tcp / tls / data / throttle (оборвалось после N КБ) / http.
package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"dpibypass/speed"
	"dpibypass/tg"
)

// Site - что проверять
type Site struct {
	Name    string   `json:"name"`
	Host    string   `json:"host"`    // главная страница
	Domains []string `json:"domains"` // домены сервиса (CDN тоже)
}

// Result - итог проверки сервиса
type Result struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Stage  string `json:"stage"`  // ok, dns, tcp, tls, data, throttle, http
	Reason string `json:"reason"` // понятное объяснение
	Ping   int    `json:"ping"`   // мс, время TCP-соединения
	KBps   int    `json:"kbps"`   // скорость на нагрузке
	Bytes  int64  `json:"bytes"`  // сколько скачано на нагрузке
	What   string `json:"what"`   // что именно качали
	Ms     int    `json:"ms"`     // сколько длилась проверка
}

// testRoots - корневые сертификаты для тестов (nil - системные)
var testRoots *x509.CertPool

// Dial - как соединяться (напрямую или через SOCKS обхода)
type Dial func(ctx context.Context, network, addr string) (net.Conn, error)

// Direct - соединение напрямую
func Direct(timeout time.Duration) Dial {
	d := &net.Dialer{Timeout: timeout}
	return d.DialContext
}

// Socks - соединение через SOCKS5 (byedpi или маршрутизатор)
func Socks(addr string) Dial {
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		type res struct {
			c   net.Conn
			err error
		}
		ch := make(chan res, 1)
		go func() { c, err := tg.SocksDial(addr, target); ch <- res{c, err} }()
		select {
		case r := <-ch:
			return r.c, r.err
		case <-ctx.Done():
			go func() {
				if r := <-ch; r.c != nil {
					r.c.Close()
				}
			}()
			return nil, ctx.Err()
		}
	}
}

// Options - насколько тщательно
type Options struct {
	Light   bool          // при переборе стратегий: меньше данных, короче таймауты
	Quick   bool          // фоновая проверка: только страница до 24 КБ, без нагрузки
	Timeout time.Duration // на всю проверку одного сервиса
}

const ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"

func client(dial Dial, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DialContext:           dial,
		TLSHandshakeTimeout:   7 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{RootCAs: testRoots},
		DisableCompression:    true,
		MaxIdleConnsPerHost:   4,
	}
	return &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 {
				return http.ErrUseLastResponse
			}
			return nil
		}}
}

// classify превращает ошибку в стадию и понятную причину
func classify(err error, got int64, phase string) (string, string) {
	var dnsErr *net.DNSError
	msg := err.Error()
	switch {
	case errors.As(err, &dnsErr):
		return "dns", "DNS не отвечает или подменён"
	case strings.Contains(msg, "no such host"):
		return "dns", "DNS не отвечает или подменён"
	case phase == "connect" && (strings.Contains(msg, "refused") || strings.Contains(msg, "unreachable") || strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline") || strings.Contains(msg, "SOCKS")):
		return "tcp", "нет TCP-соединения: блокировка по IP или сервер недоступен"
	case phase == "tls" || strings.Contains(msg, "tls:") || strings.Contains(msg, "handshake"):
		if strings.Contains(msg, "reset") || strings.Contains(msg, "EOF") {
			return "tls", "DPI сбрасывает соединение на TLS ClientHello (блок по SNI)"
		}
		if strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline") {
			return "tls", "DPI глушит TLS: ответ на ClientHello не пришёл"
		}
		return "tls", "ошибка TLS: " + short(msg)
	case got > 0:
		return "throttle", fmt.Sprintf("обрыв после %d КБ: замедление / обрыв по объёму (ТСПУ)", (got+512)>>10)
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline"):
		return "data", "после TLS данные не идут (зависание)"
	case strings.Contains(msg, "reset") || strings.Contains(msg, "EOF"):
		return "data", "соединение сброшено после TLS"
	}
	return "data", short(msg)
}

func short(s string) string {
	if i := strings.LastIndex(s, ": "); i > 0 && len(s)-i < 80 {
		s = s[i+2:]
	}
	if len(s) > 100 {
		s = s[:100]
	}
	return s
}

// ping - время TCP-соединения через dial
func ping(ctx context.Context, dial Dial, host string) (int, error) {
	t := time.Now()
	addr := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		addr = net.JoinHostPort(host, "443")
	}
	c, err := dial(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	c.Close()
	ms := int(time.Since(t).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

// fetch качает URL до max байт или до maxTime; возвращает скачанное (для страницы) и скорость
func fetch(ctx context.Context, cl *http.Client, u string, max int64, maxTime time.Duration, keep bool) (body []byte, got int64, kbps int, code int, err error) {
	// зависшее чтение (DPI молча глушит поток) не должно ждать общий таймаут
	ctx, cancel := context.WithTimeout(ctx, maxTime+6*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	defer resp.Body.Close()
	code = resp.StatusCode
	start := time.Now()
	buf := make([]byte, 32<<10)
	for got < max && time.Since(start) < maxTime {
		n, rerr := resp.Body.Read(buf)
		if keep && len(body) < 2<<20 {
			body = append(body, buf[:n]...)
		}
		got += int64(n)
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			err = rerr
			break
		}
	}
	if err == nil && got < max && time.Since(start) >= maxTime && got < 16<<10 {
		err = errors.New("timeout: данные почти не идут")
	}
	el := time.Since(start).Seconds()
	if el < 0.001 {
		el = 0.001
	}
	kbps = int(float64(got) / 1024 / el)
	return
}

var assetRe = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"'<>\s]+\.(?:js|css|png|jpe?g|webp|woff2|svg|gif)(?:\?[^"'<>\s]*)?)["']`)

// assets - ссылки на файлы сервиса на странице (свои домены и CDN)
func assets(page []byte, base *url.URL, domains []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range assetRe.FindAllSubmatch(page, 200) {
		ref, err := url.Parse(strings.ReplaceAll(string(m[1]), "&amp;", "&"))
		if err != nil {
			continue
		}
		u := base.ResolveReference(ref)
		if u.Scheme != "https" || seen[u.String()] {
			continue
		}
		h := strings.ToLower(u.Hostname())
		ok := false
		for _, d := range domains {
			if h == d || strings.HasSuffix(h, "."+d) {
				ok = true
			}
		}
		if ok {
			seen[u.String()] = true
			out = append(out, u.String())
		}
	}
	// сначала скрипты: они крупнее
	sort.SliceStable(out, func(i, j int) bool {
		return strings.Contains(out[i], ".js") && !strings.Contains(out[j], ".js")
	})
	return out
}

// Run проверяет сервис
func Run(ctx context.Context, s Site, dial Dial, o Options) (r Result) {
	if o.Timeout == 0 {
		o.Timeout = 25 * time.Second
		if o.Light {
			o.Timeout = 14 * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	start := time.Now()
	r = Result{Name: s.Name}
	defer func() { r.Ms = int(time.Since(start).Milliseconds()) }()

	if s.Name == "Telegram" {
		r = telegram(ctx, dial)
		r.Name = s.Name
		return r
	}

	p, err := ping(ctx, dial, s.Host)
	if err != nil {
		r.Stage, r.Reason = classify(err, 0, "connect")
		return r
	}
	r.Ping = p
	cl := client(dial, o.Timeout)
	defer cl.CloseIdleConnections()

	pageMax := int64(512 << 10)
	if o.Light {
		pageMax = 128 << 10
	}
	if o.Quick {
		pageMax = 24 << 10
	}
	page, got, kbps, code, err := fetch(ctx, cl, "https://"+s.Host+"/", pageMax, 8*time.Second, true)
	if err != nil {
		phase := "data"
		if got == 0 && code == 0 {
			phase = "tls"
		}
		r.Stage, r.Reason = classify(err, got, phase)
		return r
	}
	if code >= 500 {
		r.Stage, r.Reason = "http", fmt.Sprintf("сервер ответил HTTP %d", code)
		return r
	}
	r.Bytes, r.KBps, r.What = got, kbps, "страница"
	if o.Quick {
		r.OK, r.Stage = true, "ok"
		return r
	}

	// нагрузка
	switch s.Name {
	case "YouTube":
		maxT := 6 * time.Second
		if o.Light {
			maxT = 3 * time.Second
		}
		maxB := int64(8 << 20)
		if o.Light {
			maxB = 2 << 20
		}
		sp, err := speed.YouTubeVideoMax(cl, maxT, maxB)
		if err != nil {
			// страница есть, видео нет - типичное замедление googlevideo
			r.Stage, r.Reason = "throttle", "страница открывается, видео googlevideo - нет: "+short(err.Error())
			return r
		}
		r.KBps, r.Bytes, r.What = sp.KBps, sp.Bytes, "видео "+sp.Host
		if sp.Bytes < 256<<10 {
			r.Stage, r.Reason = "throttle", fmt.Sprintf("видео оборвалось после %d КБ", sp.Bytes>>10)
			return r
		}
	case "Discord":
		if err := discordGateway(ctx, dial); err != nil {
			r.Stage, r.Reason = "tls", "шлюз gateway.discord.gg: "+short(err.Error())
			return r
		}
		fallthrough
	default:
		base, _ := url.Parse("https://" + s.Host + "/")
		list := assets(page, base, s.Domains)
		amax := int64(1 << 20)
		if o.Light {
			amax = 256 << 10
		}
		for i, a := range list {
			if i >= 3 {
				break
			}
			_, ag, ak, acode, aerr := fetch(ctx, cl, a, amax, 6*time.Second, false)
			if aerr != nil && ag == 0 {
				st, rs := classify(aerr, ag, "data")
				r.Stage, r.Reason = st, "файл CDN: "+rs
				continue
			}
			if acode >= 400 {
				continue
			}
			if aerr != nil && ag < 64<<10 {
				r.Stage, r.Reason = classify(aerr, ag, "data")
				return r
			}
			r.KBps, r.Bytes, r.What = ak, ag, "файл "+hostOf(a)
			r.Stage, r.Reason = "", ""
			break
		}
		if r.Stage != "" {
			return r
		}
	}
	r.OK, r.Stage = true, "ok"
	return r
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil {
		return p.Hostname()
	}
	return u
}

// telegram: так, как Telegram работает через обход. Серверы Telegram (DC) у большинства провайдеров
// заблокированы по IP - стратегия обхода DPI это не исправит, поэтому главный путь - WebSocket к
// web.telegram.org (TLS, его маскирует стратегия). Сначала WebSocket, затем, если не вышло, прямой
// MTProto к DC2 (там, где серверы не заблокированы). Ошибка прямого пути - «блок по IP», не DPI.
func telegram(ctx context.Context, dial Dial) Result {
	r := Result{}
	dl, _ := ctx.Deadline()
	t := time.Until(dl)
	if t > 12*time.Second {
		t = 12 * time.Second
	}
	d1 := func(addr string) (net.Conn, error) { return dial(ctx, "tcp", addr) }
	if d, err := tg.CheckWS(d1, t); err == nil {
		r.OK, r.Stage, r.Ping, r.What = true, "ok", int(d.Milliseconds()), "WebSocket web.telegram.org"
		return r
	} else {
		wsErr := err
		if d2, err := tg.CheckDC(d1, 2, t/2+time.Second); err == nil {
			r.OK, r.Stage, r.Ping, r.What = true, "ok", int(d2.Milliseconds()), "MTProto DC2"
			return r
		}
		st, rs := classify(wsErr, 0, "tls")
		r.Stage, r.Reason = st, "WebSocket web.telegram.org: "+rs
		return r
	}
}

// RunAll проверяет несколько сервисов параллельно
func RunAll(ctx context.Context, sites []Site, dial Dial, o Options, each func(Result)) map[string]Result {
	var mu sync.Mutex
	out := map[string]Result{}
	var wg sync.WaitGroup
	for _, s := range sites {
		wg.Add(1)
		go func(s Site) {
			defer wg.Done()
			r := Run(ctx, s, dial, o)
			mu.Lock()
			out[s.Name] = r
			mu.Unlock()
			if each != nil {
				each(r)
			}
		}(s)
	}
	wg.Wait()
	return out
}
