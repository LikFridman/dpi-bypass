package tg

// Поиск публичных MTProto-прокси: скачиваем свежие списки, проверяем каждый
// настоящим запросом к Telegram (req_pq через прокси) и возвращаем самые быстрые.

import (
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultSources - списки публичных прокси (обновляются их авторами каждый час/день).
// Можно заменить через tg_proxy_sources в update/update.json.
var DefaultSources = []string{
	"https://raw.githubusercontent.com/Argh94/Proxy-List/main/MTProto.txt",
	"https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
	"https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
	"https://raw.githubusercontent.com/Kudts/mtproto/main/all_proxies.txt",
}

// Found - проверенный прокси.
type Found struct {
	Link string `json:"link"` // tg://proxy?... - можно открыть прямо в Telegram
	Name string `json:"name"` // host:port
	Kind string `json:"kind"` // MTProto / FakeTLS
	Ms   int    `json:"ms"`   // время ответа Telegram через прокси
}

var linkRe = regexp.MustCompile(`(?i)(?:tg://proxy|https?://t\.me/proxy)\?[^\s"'<>\x60]+`)

// ExtractLinks достаёт ссылки на MTProto-прокси из любого текста.
func ExtractLinks(text string) []string {
	return linkRe.FindAllString(text, -1)
}

// FetchCandidates скачивает списки и возвращает уникальные прокси (перемешанные).
func FetchCandidates(sources []string, client *http.Client, log func(string, ...any)) []Upstream {
	var mu sync.Mutex
	var wg sync.WaitGroup
	seen := map[string]bool{}
	var out []Upstream
	for _, src := range sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			resp, err := client.Get(src)
			if (err != nil || resp.StatusCode != 200) && jsdelivr(src) != "" {
				if resp != nil {
					resp.Body.Close()
				}
				resp, err = client.Get(jsdelivr(src)) // зеркало, если GitHub недоступен
			}
			if err != nil {
				if log != nil {
					log("Telegram: список %s недоступен (%v)", shortSrc(src), shortErrMsg(err))
				}
				return
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			resp.Body.Close()
			if resp.StatusCode != 200 {
				return
			}
			n := 0
			for _, l := range ExtractLinks(string(b)) {
				u, err := ParseUpstream(strings.ReplaceAll(l, "&amp;", "&"))
				if err != nil || u.Kind != "mtproto" {
					continue
				}
				mu.Lock()
				if !seen[u.Addr] {
					seen[u.Addr] = true
					out = append(out, u)
					n++
				}
				mu.Unlock()
			}
			if log != nil {
				log("Telegram: из %s взято %d прокси", shortSrc(src), n)
			}
		}(src)
	}
	wg.Wait()
	// перемешать, чтобы не проверять всегда одни и те же из начала списков
	for i := len(out) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return out
}

// jsdelivr - зеркало файла с raw.githubusercontent.com
func jsdelivr(src string) string {
	const pfx = "https://raw.githubusercontent.com/"
	if !strings.HasPrefix(src, pfx) {
		return ""
	}
	p := strings.SplitN(strings.TrimPrefix(src, pfx), "/", 4) // user, repo, branch, path
	if len(p) < 4 {
		return ""
	}
	return "https://cdn.jsdelivr.net/gh/" + p[0] + "/" + p[1] + "@" + p[2] + "/" + p[3]
}

func shortSrc(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "raw.githubusercontent.com/")
	if i := strings.Index(s, "/"); i > 0 {
		if j := strings.Index(s[i+1:], "/"); j > 0 {
			return s[:i+1+j]
		}
	}
	return s
}

// CheckUpstream проверяет внешний прокси настоящим запросом к Telegram (DC2).
func CheckUpstream(u Upstream, timeout time.Duration) (time.Duration, error) {
	secret := make([]byte, 16)
	rand.Read(secret)
	px := &TGProxy{Secret: secret}
	r := u.Route()
	px.Routes = func() []TGRoute { return []TGRoute{r} }
	if err := px.Listen("127.0.0.1:0"); err != nil {
		return 0, err
	}
	defer px.Close()
	return CheckTimeout(px.Addr(), secret, 2, timeout)
}

// Link - ссылка tg://proxy для этого прокси
func (u Upstream) Link() string {
	host, port, _ := net.SplitHostPort(u.Addr)
	sec := "dd" + hexStr(u.Key)
	if u.Domain != "" {
		sec = "ee" + hexStr(u.Key) + hexStr([]byte(u.Domain))
	}
	return "tg://proxy?server=" + host + "&port=" + port + "&secret=" + sec
}

func hexStr(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = h[c>>4], h[c&15]
	}
	return string(out)
}

// Discover проверяет кандидатов параллельно и возвращает want самых быстрых.
// Останавливается раньше, когда набралось достаточно рабочих прокси.
func Discover(ctx context.Context, cands []Upstream, want int, log func(string, ...any)) []Found {
	const workers = 48
	enough := want * 4
	var mu sync.Mutex
	var ok []Found
	jobs := make(chan Upstream)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				d, err := CheckUpstream(u, 7*time.Second)
				if err != nil {
					continue
				}
				kind := "MTProto"
				if u.Domain != "" {
					kind = "FakeTLS"
				}
				mu.Lock()
				ok = append(ok, Found{Link: u.Link(), Name: u.Addr, Kind: kind, Ms: int(d.Milliseconds())})
				if len(ok) >= enough {
					cancel()
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, u := range cands {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- u:
		}
	}
	close(jobs)
	wg.Wait()

	// лучшие - перепроверить ещё раз и взять среднее, чтобы случайный быстрый ответ не обманул
	sort.Slice(ok, func(i, j int) bool { return ok[i].Ms < ok[j].Ms })
	working := len(ok)
	if len(ok) > want*2 {
		ok = ok[:want*2]
	}
	var wg2 sync.WaitGroup
	for i := range ok {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			u, err := ParseUpstream(ok[i].Link)
			if err != nil {
				return
			}
			if d, err := CheckUpstream(u, 7*time.Second); err == nil {
				ok[i].Ms = (ok[i].Ms + int(d.Milliseconds())) / 2
			} else {
				ok[i].Ms += 5000 // второй раз не ответил - в конец
			}
		}(i)
	}
	wg2.Wait()
	sort.Slice(ok, func(i, j int) bool { return ok[i].Ms < ok[j].Ms })
	var out []Found
	for _, f := range ok {
		if f.Ms < 5000 && len(out) < want {
			out = append(out, f)
		}
	}
	if log != nil {
		log("Telegram: найдено рабочих прокси %d, выбраны %d лучших", working, len(out))
	}
	return out
}
