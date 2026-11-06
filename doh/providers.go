package doh

import (
	"context"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Provider - публичный сервер зашифрованного DNS. IPs - адреса для подключения без обычного DNS
// (провайдер не узнает и не подменит, куда мы идём за адресами).
type Provider struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Note string   `json:"note"`
	URL  string   `json:"url"`
	IPs  []string `json:"ips"`
}

// Providers - на выбор во вкладке DNS ("auto" - самый быстрый из основных)
var Providers = []Provider{
	{"cloudflare", "Cloudflare", "быстрый, без фильтрации", "https://cloudflare-dns.com/dns-query", []string{"1.1.1.1", "1.0.0.1"}},
	{"google", "Google", "надёжный, без фильтрации", "https://dns.google/dns-query", []string{"8.8.8.8", "8.8.4.4"}},
	{"quad9", "Quad9", "блокирует вредоносные сайты", "https://dns.quad9.net/dns-query", []string{"9.9.9.9", "149.112.112.112"}},
	{"adguard", "AdGuard", "блокирует рекламу и трекеры", "https://dns.adguard-dns.com/dns-query", []string{"94.140.14.14", "94.140.15.15"}},
	{"adguard-family", "AdGuard Family", "реклама + сайты для взрослых, безопасный поиск", "https://family.adguard-dns.com/dns-query", []string{"94.140.14.15", "94.140.15.16"}},
	{"cloudflare-family", "Cloudflare Family", "без вредоносных и взрослых сайтов", "https://family.cloudflare-dns.com/dns-query", []string{"1.1.1.3", "1.0.0.3"}},
	{"mullvad", "Mullvad", "без логов, без фильтрации", "https://dns.mullvad.net/dns-query", []string{"194.242.2.2"}},
	{"comss", "Comss.one", "РФ: открывает часть сервисов, недоступных из России (ИИ, игры)", "https://dns.comss.one/dns-query", []string{"195.133.25.16"}},
}

// AutoIDs - из чего выбирает Auto
var AutoIDs = []string{"cloudflare", "google", "quad9"}

func ProviderByID(id string) (Provider, bool) {
	for _, p := range Providers {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// bootDial: имя сервера DoH -> его известные адреса (подключаемся по IP, SNI - по имени)
func bootDial(base Dial, boot map[string][]string) Dial {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		ips := boot[strings.ToLower(host)]
		if err != nil || len(ips) == 0 {
			return base(ctx, network, addr)
		}
		var last error
		for _, ip := range ips {
			c, err := base(ctx, network, net.JoinHostPort(ip, port))
			if err == nil {
				return c, nil
			}
			last = err
		}
		return nil, last
	}
}

// NewFor - резолвер для выбранного сервера ("auto" или "" - Cloudflare/Google/Quad9 по очереди,
// custom - свой адрес https://.../dns-query). Если выбранный не отвечает - запасные (Cloudflare, Google).
func NewFor(id, custom string, dial, fallback Dial) *Resolver {
	switch {
	case id == "custom" && strings.HasPrefix(custom, "https://"):
		return NewProvider(&Provider{ID: "custom", Name: "Custom", URL: custom}, dial, fallback)
	case id != "" && id != "auto":
		if p, ok := ProviderByID(id); ok {
			return NewProvider(&p, dial, fallback)
		}
	}
	return NewProvider(nil, dial, fallback)
}

// NewProvider - резолвер с сервером p первым (nil - Auto) и запасными из AutoIDs
func NewProvider(p *Provider, dial, fallback Dial) *Resolver {
	var list []Provider
	if p != nil && strings.HasPrefix(p.URL, "https://") {
		list = append(list, *p)
	}
	for _, a := range AutoIDs {
		if x, ok := ProviderByID(a); ok && (len(list) == 0 || list[0].URL != x.URL) {
			list = append(list, x)
		}
	}
	urls := make([]string, 0, len(list))
	boot := map[string][]string{}
	for _, x := range list {
		urls = append(urls, x.URL)
		if u, err := url.Parse(x.URL); err == nil && len(x.IPs) > 0 {
			boot[strings.ToLower(u.Hostname())] = x.IPs
		}
	}
	r := newResolver(urls, dial, fallback, boot)
	r.primary = p != nil && len(list) > 0 && list[0].URL == p.URL
	return r
}

// SetProviders - заменить список (новые серверы из update.json; пустой - не трогать)
func SetProviders(l []Provider) {
	var ok []Provider
	for _, p := range l {
		if p.ID != "" && p.Name != "" && strings.HasPrefix(p.URL, "https://") {
			ok = append(ok, p)
		}
	}
	if len(ok) > 0 {
		Providers = ok
	}
}

// PingResult - задержка до сервера DoH (запрос через зашифрованный канал)
type PingResult struct {
	ID    string `json:"id"`
	Ms    int    `json:"ms"`
	Error string `json:"error,omitempty"`
}

// PingAll - проверить все серверы (и свой адрес, если задан) параллельно
func PingAll(ctx context.Context, custom string, dial Dial) []PingResult {
	return PingList(ctx, Providers, custom, dial)
}

// PingList - то же для заданного списка серверов
func PingList(ctx context.Context, providers []Provider, custom string, dial Dial) []PingResult {
	list := append([]Provider{}, providers...)
	if strings.HasPrefix(custom, "https://") {
		list = append(list, Provider{ID: "custom", URL: custom})
	}
	out := make([]PingResult, len(list))
	var wg sync.WaitGroup
	for i, p := range list {
		wg.Add(1)
		go func(i int, p Provider) {
			defer wg.Done()
			boot := map[string][]string{}
			if u, err := url.Parse(p.URL); err == nil && len(p.IPs) > 0 {
				boot[strings.ToLower(u.Hostname())] = p.IPs
			}
			r := newResolver([]string{p.URL}, dial, nil, boot)
			q := BuildQuery("www.google.com", 1)
			// первый запрос - установка соединения; меряем второй (как в работе: соединение держится)
			c, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			if _, err := r.race(c, r.clients[0], q); err != nil {
				out[i] = PingResult{ID: p.ID, Error: shortErr(err)}
				return
			}
			t := time.Now()
			if _, err := r.race(c, r.clients[0], q); err != nil {
				out[i] = PingResult{ID: p.ID, Error: shortErr(err)}
				return
			}
			out[i] = PingResult{ID: p.ID, Ms: int(time.Since(t).Milliseconds())}
		}(i, p)
	}
	wg.Wait()
	sort.SliceStable(out, func(a, b int) bool {
		if (out[a].Error == "") != (out[b].Error == "") {
			return out[a].Error == ""
		}
		return out[a].Ms < out[b].Ms
	})
	return out
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// Current - какой сервер ответил последним (для экрана)
func (r *Resolver) Current() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.good < len(r.endpoints) {
		return r.endpoints[r.good]
	}
	return ""
}
