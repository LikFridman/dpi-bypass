//go:build windows

package main

// Ping all, ручной выбор стратегии для сервиса и результаты проверок стратегий.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dpibypass/check"
)

// ---------- проверка сервиса с нагрузкой ----------

func checkSite(s Service) check.Site {
	return check.Site{Name: s.Name, Host: s.Probes[0], Domains: s.Domains}
}

func winDial() check.Dial { return newDialer(6 * time.Second).DialContext }

func kbText(k int) string {
	if k >= 1024 {
		return fmt.Sprintf("%.1f MB/s", float64(k)/1024)
	}
	return fmt.Sprintf("%d KB/s", k)
}

func checkLine(r check.Result) string {
	if r.OK {
		s := fmt.Sprintf("✓ %s · %d ms", r.Name, r.Ping)
		if r.KBps > 0 {
			s += " · " + kbText(r.KBps)
		}
		if r.What != "" {
			s += " · " + r.What
		}
		return s
	}
	return fmt.Sprintf("✗ %s · %s: %s", r.Name, r.Stage, r.Reason)
}

// ---------- результаты проверок стратегий (для окна выбора) ----------

type stratRes struct {
	OK     bool   `json:"ok"`
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
	Ping   int    `json:"ping"`
	KBps   int    `json:"kbps"`
	Full   bool   `json:"full"`
	At     int64  `json:"at"`
}

var (
	resMu    sync.Mutex
	resCache map[string]map[string]stratRes // стратегия -> сервис -> результат
)

func resPath() string { return filepath.Join(dataDir, "strategy-results.json") }

func loadResults() map[string]map[string]stratRes {
	resMu.Lock()
	defer resMu.Unlock()
	if resCache == nil {
		resCache = map[string]map[string]stratRes{}
		if b, err := os.ReadFile(resPath()); err == nil {
			json.Unmarshal(b, &resCache)
		}
	}
	return resCache
}

func recordResult(id, svc string, r stratRes) {
	loadResults()
	resMu.Lock()
	defer resMu.Unlock()
	if resCache[id] == nil {
		resCache[id] = map[string]stratRes{}
	}
	r.At = time.Now().Unix()
	resCache[id][svc] = r
	if b, err := json.Marshal(resCache); err == nil {
		os.WriteFile(resPath(), b, 0644)
	}
}

func fromCheck(r check.Result, full bool) stratRes {
	return stratRes{OK: r.OK, Stage: r.Stage, Reason: r.Reason, Ping: r.Ping, KBps: r.KBps, Full: full}
}

// ---------- Ping all ----------

var (
	pingMu  sync.Mutex
	pingRes map[string]check.Result
	pingAt  time.Time
	pinging atomic.Bool
)

func pingAllAsync() {
	if !pinging.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer pinging.Store(false)
		var sites []check.Site
		for _, s := range activeServices(cachedServices()) {
			sites = append(sites, checkSite(s))
		}
		how := "без обхода"
		if engRunning.Load() {
			how = "через обход"
		}
		info("━━ Ping all (%s) ━━", how)
		res := check.RunAll(context.Background(), sites, winDial(), check.Options{}, nil)
		ok := 0
		for _, s := range sites {
			r := res[s.Name]
			if r.OK {
				ok++
				info("  %s", checkLine(r))
			} else {
				warn("  %s", checkLine(r))
			}
		}
		info("Работают %d из %d", ok, len(sites))
		pingMu.Lock()
		pingRes, pingAt = res, time.Now()
		pingMu.Unlock()
		uiToast(fmt.Sprintf("Ping all: %d/%d work", ok, len(sites)))
	}()
}

func lastPing() (map[string]check.Result, time.Time) {
	pingMu.Lock()
	defer pingMu.Unlock()
	return pingRes, pingAt
}

// ---------- ручной выбор ----------

func currentStrategyFor(cfg *Config, svc string) string {
	if cfg == nil {
		return ""
	}
	for _, g := range cfg.Groups {
		for _, n := range g.Services {
			if n == svc {
				return g.Strategy
			}
		}
	}
	return ""
}

func siteStrategiesJSON(svc string) any {
	cfg := loadConfigCached()
	res := loadResults()
	type row struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Args   string `json:"args"`
		Tested bool   `json:"tested"`
		stratRes
	}
	var list []row
	for _, st := range orderedStrategies() {
		r, ok := res[st.ID][svc]
		list = append(list, row{ID: st.ID, Name: st.Name, Args: strings.Join(st.Args, " "), Tested: ok, stratRes: r})
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.OK != b.OK {
			return a.OK
		}
		if a.KBps != b.KBps {
			return a.KBps > b.KBps
		}
		return a.Tested && !b.Tested
	})
	pinned := ""
	if cfg != nil {
		pinned = cfg.Pins[svc]
	}
	return map[string]any{"site": svc, "current": currentStrategyFor(cfg, svc), "pinned": pinned, "list": list}
}

// testOneStrategy: обход ненадолго выключается, стратегия проверяется на сервисе с нагрузкой
func testOneStrategy(svc, id string) {
	st, ok := strategyByID(id)
	var s *Service
	for _, x := range cachedServices() {
		if x.Name == svc {
			x := x
			s = &x
		}
	}
	if !ok || s == nil {
		uiToast("Нет такой стратегии или сервиса")
		return
	}
	webOp(func() {
		wasRunning, mode := engRunning.Load(), runMode
		if wasRunning {
			info("Проверка стратегии: обход выключен на несколько секунд")
			stopEngine()
		}
		defer func() {
			if wasRunning {
				webStartEngine(mode, false)
			}
			uiEvent(map[string]any{"t": "stratUpdated", "site": svc})
		}()
		setStatus("Testing " + id + " on " + svc)
		w, err := startWinws(testArgs(st))
		if err != nil {
			warn("%s: winws не запустился: %v", st.Name, err)
			uiToast("winws не запустился")
			return
		}
		r := check.Run(context.Background(), checkSite(*s), winDial(), check.Options{})
		w.Stop()
		recordResult(id, svc, fromCheck(r, true))
		if r.OK {
			info("Проверка %s для %s: %s", st.Name, svc, checkLine(r))
		} else {
			warn("Проверка %s для %s: %s", st.Name, svc, checkLine(r))
		}
		uiToast(checkLine(r))
	})
}

// NoneID - выбор «без обхода» для сервиса
const NoneID = "none"

// serviceActive: сервис отмечен пользователем (Sites → Choose) и для него не выбран None
func serviceActive(name string) bool { return serviceActiveIn(loadConfigCached(), name) }

func serviceActiveIn(cfg *Config, name string) bool {
	if cfg != nil && cfg.Pins[name] == NoneID {
		return false
	}
	if !settings.SitesSet {
		return true
	}
	for _, n := range settings.Sites {
		if n == name {
			return true
		}
	}
	return false
}

// serviceChosen: отмечен ли сервис в Sites → Choose
func serviceChosen(name string) bool {
	for _, n := range settings.Sites {
		if n == name {
			return true
		}
	}
	return false
}

func activeServices(all []Service) []Service {
	var out []Service
	for _, s := range all {
		if serviceActive(s.Name) {
			out = append(out, s)
		}
	}
	return out
}

// dropService убирает сервис из групп стратегий: его трафик идёт без обхода
func dropService(cfg *Config, svc string) {
	var groups []Group
	for _, g := range cfg.Groups {
		var keep []string
		for _, n := range g.Services {
			if n != svc {
				keep = append(keep, n)
			}
		}
		g.Services = keep
		if len(keep) > 0 {
			groups = append(groups, g)
		}
	}
	cfg.Groups = groups
	delete(cfg.Unfixable, svc)
}

// applyPins переносит закреплённые сервисы в группы с выбранными стратегиями;
// сервисы с None и не выбранные пользователем - убираются из групп (без обхода)
func applyPins(cfg *Config) {
	for _, s := range cachedServices() {
		if !serviceActiveIn(cfg, s.Name) {
			dropService(cfg, s.Name)
		}
	}
	for svc, id := range cfg.Pins {
		if _, ok := strategyByID(id); !ok {
			continue
		}
		var groups []Group
		for _, g := range cfg.Groups {
			var keep []string
			for _, n := range g.Services {
				if n != svc {
					keep = append(keep, n)
				}
			}
			g.Services = keep
			if len(keep) > 0 {
				groups = append(groups, g)
			}
		}
		added := false
		for i := range groups {
			if groups[i].Strategy == id {
				groups[i].Services = append(groups[i].Services, svc)
				added = true
			}
		}
		if !added {
			groups = append(groups, Group{Strategy: id, Services: []string{svc}})
		}
		cfg.Groups = groups
		delete(cfg.Unfixable, svc)
	}
}

func pinStrategy(svc, id string) {
	cfg := loadConfig()
	if cfg == nil {
		uiToast("Сначала включи обход, чтобы подобрались стратегии")
		return
	}
	if cfg.Pins == nil {
		cfg.Pins = map[string]string{}
	}
	if id == "" {
		delete(cfg.Pins, svc)
		info("%s: снова автоматический выбор (применится при следующем подборе)", svc)
	} else {
		cfg.Pins[svc] = id
		applyPins(cfg)
		if id == NoneID {
			info("%s: без обхода (None) - напрямую, как без программы", svc)
		} else {
			st, _ := strategyByID(id)
			info("%s: закреплена стратегия %s", svc, st.Name)
		}
	}
	saveConfig(cfg)
	uiEvent(map[string]any{"t": "stratUpdated", "site": svc})
	if engRunning.Load() {
		mode := runMode
		go func() {
			stopEngine()
			webStartEngine(mode, false)
		}()
	}
}
