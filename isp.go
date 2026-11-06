//go:build windows

package main

// Провайдер: определяем номер автономной системы (AS) и сначала пробуем
// стратегии, которые у этого провайдера уже срабатывали - по общим пресетам
// из update/update.json и по собственному опыту на этом компьютере.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type ISPInfo struct {
	ASN     string // "AS12389"
	Name    string // "Rostelecom"
	IP      string // внешний IP мимо VPN (для отчётов)
	City    string
	Country string
}

var (
	ispMu     sync.Mutex
	ispCached *ISPInfo
	ispAt     time.Time
)

// известные провайдеры - чтобы показывать понятное название
var knownISPs = map[string]string{
	"AS12389": "Ростелеком", "AS8359": "МТС", "AS3216": "Билайн", "AS16345": "Билайн",
	"AS8402": "Билайн (Корбина)", "AS31133": "МегаФон", "AS25159": "МегаФон", "AS9049": "Дом.ру (ЭР-Телеком)",
	"AS15378": "Т2 (Tele2)", "AS25513": "МГТС", "AS20485": "ТрансТелеКом", "AS24955": "Уфанет",
	"AS28840": "Таттелеком",
}

var asnRe = regexp.MustCompile(`AS\d+`)

func ispClient() *http.Client {
	// запрос мимо VPN - нужен настоящий провайдер
	return &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{Proxy: nil,
		DialContext: newDialer(5 * time.Second).DialContext}}
}

func fetchISP() *ISPInfo {
	cl := ispClient()
	// 1) ip-api.com
	if resp, err := cl.Get("http://ip-api.com/json/?fields=status,isp,org,as,query,city,country"); err == nil {
		var r struct{ Status, ISP, Org, AS, Query, City, Country string }
		json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&r)
		resp.Body.Close()
		if asn := asnRe.FindString(r.AS); asn != "" {
			return &ISPInfo{ASN: asn, Name: firstNonEmpty(r.ISP, r.Org), IP: r.Query, City: r.City, Country: r.Country}
		}
	}
	// 2) ipinfo.io
	if resp, err := cl.Get("https://ipinfo.io/json"); err == nil {
		var r struct{ Org, IP, City, Country string }
		json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&r)
		resp.Body.Close()
		if asn := asnRe.FindString(r.Org); asn != "" {
			return &ISPInfo{ASN: asn, Name: strings.TrimSpace(strings.TrimPrefix(r.Org, asn)), IP: r.IP, City: r.City, Country: r.Country}
		}
	}
	return nil
}

func currentISP() ISPInfo {
	ispMu.Lock()
	defer ispMu.Unlock()
	if ispCached == nil || time.Since(ispAt) > 10*time.Minute {
		if i := fetchISP(); i != nil {
			ispCached, ispAt = i, time.Now()
		}
	}
	if ispCached == nil {
		return ISPInfo{}
	}
	return *ispCached
}

// refreshISP - забыть провайдера (после смены сети), следующий currentISP спросит заново
func refreshISP() {
	ispMu.Lock()
	ispCached = nil
	ispMu.Unlock()
}

// netSignature - какие интернет-адаптеры и адреса сейчас (меняется при смене сети)
func netSignature() string {
	var parts []string
	for _, a := range listAdapters() {
		if a.Gateway && !isVPNAdapter(a) {
			parts = append(parts, a.GUID+"="+strings.Join(a.IPs, ","))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func ispTitle(i ISPInfo) string {
	if i.ASN == "" {
		return "не определён"
	}
	if n, ok := knownISPs[i.ASN]; ok {
		return fmt.Sprintf("%s (%s)", n, i.ASN)
	}
	return fmt.Sprintf("%s (%s)", firstNonEmpty(i.Name, "?"), i.ASN)
}

func showISP() {
	i := currentISP()
	info("Провайдер: %s", ispTitle(i))
	if p := ispPreset(i.ASN); len(p) > 0 {
		say("      Сначала пробую стратегии, которые у этого провайдера обычно работают: %s", strings.Join(p, ", "))
	}
}

// ---------- пресеты и опыт ----------

var remotePresets = map[string][]string{} // из update.json: AS -> стратегии

func ispResultsFile() string { return filepath.Join(dataDir, "isp-results.json") }

// локальный опыт: AS -> стратегия -> сколько раз сработала
func loadISPResults() map[string]map[string]int {
	res := map[string]map[string]int{}
	if b, err := os.ReadFile(ispResultsFile()); err == nil {
		json.Unmarshal(b, &res)
	}
	return res
}

func recordISPResult(ids []string) {
	asn := currentISP().ASN
	if asn == "" || len(ids) == 0 {
		return
	}
	res := loadISPResults()
	if res[asn] == nil {
		res[asn] = map[string]int{}
	}
	for _, id := range ids {
		res[asn][id]++
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	os.WriteFile(ispResultsFile(), b, 0644)
}

// ispPreset - порядок стратегий для провайдера: свой опыт, затем общий пресет
func ispPreset(asn string) []string {
	if asn == "" {
		return nil
	}
	var ids []string
	seen := map[string]bool{}
	if mine := loadISPResults()[asn]; len(mine) > 0 {
		type kv struct {
			id string
			n  int
		}
		var l []kv
		for id, n := range mine {
			l = append(l, kv{id, n})
		}
		sort.Slice(l, func(a, b int) bool { return l[a].n > l[b].n || (l[a].n == l[b].n && l[a].id < l[b].id) })
		for _, x := range l {
			if _, ok := strategyByID(x.id); ok && !seen[x.id] {
				seen[x.id] = true
				ids = append(ids, x.id)
			}
		}
	}
	for _, id := range remotePresets[asn] {
		if _, ok := strategyByID(id); ok && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

// orderedStrategies - все стратегии, подходящие провайдеру - первыми
func orderedStrategies() []Strategy {
	first := ispPreset(currentISP().ASN)
	pos := map[string]int{}
	for i, id := range first {
		pos[id] = i
	}
	list := append([]Strategy{}, strategies...)
	sort.SliceStable(list, func(a, b int) bool {
		pa, oka := pos[list[a].ID]
		pb, okb := pos[list[b].ID]
		switch {
		case oka && okb:
			return pa < pb
		default:
			return oka && !okb
		}
	})
	return list
}

// shareURL - ссылка на новую задачу в GitHub с результатом (пользователь отправляет сам)
func shareURL(cfg *Config) string {
	i := currentISP()
	var lines []string
	lines = append(lines, "Провайдер: "+ispTitle(i), "Версия: "+version, "", "Сработавшие стратегии:")
	for _, g := range cfg.Groups {
		st, _ := strategyByID(g.Strategy)
		lines = append(lines, fmt.Sprintf("- `%s` %s: %s", st.ID, st.Name, strings.Join(g.Services, ", ")))
		lines = append(lines, "  `"+strings.Join(st.Args, " ")+"`")
	}
	for d, id := range cfg.Sites {
		lines = append(lines, fmt.Sprintf("- сайт %s: `%s`", d, id))
	}
	if len(cfg.Unfixable) > 0 {
		lines = append(lines, "", "Не открылись:")
		for n, r := range cfg.Unfixable {
			lines = append(lines, "- "+n+": "+r)
		}
	}
	q := url.Values{}
	q.Set("title", "Результат: "+ispTitle(i))
	q.Set("labels", "результат")
	q.Set("body", strings.Join(lines, "\n"))
	return "https://github.com/LikFridman/dpi-bypass/issues/new?" + q.Encode()
}
