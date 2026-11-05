//go:build windows

package main

// Обновление стратегий и списка сервисов из репозитория на GitHub.
// Файл update/update.json можно менять в репозитории - программа подтянет
// новые стратегии при следующем запуске, без новой версии exe.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var updateURLs = []string{
	"https://raw.githubusercontent.com/LikFridman/dpi-bypass/main/update/update.json",
	"https://cdn.jsdelivr.net/gh/LikFridman/dpi-bypass@main/update/update.json",
}

var builtinID = map[string]bool{}

type remoteUpdate struct {
	Version    int        `json:"version"`
	Updated    string     `json:"updated"`
	Strategies []Strategy `json:"strategies"`
	Services   []string   `json:"services"` // строки в формате sites.txt
	// пресеты провайдеров: "AS12389": ["s1", "u2"] - какие стратегии пробовать первыми
	Presets map[string][]string `json:"presets"`
}

func updateCache() string { return filepath.Join(dataDir, "update.json") }

func fetchUpdate() (*remoteUpdate, error) {
	cl := &http.Client{Timeout: 8 * time.Second}
	var lastErr error
	for _, u := range updateURLs {
		resp, err := cl.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		var ru remoteUpdate
		if err := json.Unmarshal(b, &ru); err != nil {
			lastErr = err
			continue
		}
		os.WriteFile(updateCache(), b, 0644)
		return &ru, nil
	}
	return nil, lastErr
}

func loadCachedUpdate() *remoteUpdate {
	b, err := os.ReadFile(updateCache())
	if err != nil {
		return nil
	}
	var ru remoteUpdate
	if json.Unmarshal(b, &ru) != nil {
		return nil
	}
	return &ru
}

// applyUpdates скачивает обновления (или берёт сохранённые) и добавляет новые стратегии и сервисы.
func applyUpdates() {
	if len(builtinID) == 0 {
		for _, s := range strategies {
			builtinID[s.ID] = true
		}
	}
	ru, err := fetchUpdate()
	src := "с GitHub"
	if err != nil {
		if ru = loadCachedUpdate(); ru == nil {
			info("Обновления стратегий недоступны (%s) - работаю со встроенными.", shortErr(err))
			return
		}
		src = "сохранённые"
	}

	// новые стратегии ставим в начало: их добавляют, когда провайдеры меняют блокировки
	seen := map[string]bool{}
	for _, s := range strategies {
		seen[strings.Join(s.Args, " ")] = true
	}
	var added []Strategy
	for _, s := range ru.Strategies {
		key := strings.Join(s.Args, " ")
		if !validStrategy(s) || seen[key] || builtinID[s.ID] {
			continue
		}
		s.ID = "u-" + strings.TrimPrefix(s.ID, "u-")
		if _, dup := strategyByID(s.ID); dup {
			continue
		}
		seen[key] = true
		added = append(added, s)
	}
	strategies = append(added, strategies...)

	// новые сервисы дописываем в sites.txt (если такого названия ещё нет)
	newSvc := 0
	if b, err := os.ReadFile(sitesPath()); err == nil {
		have := map[string]bool{}
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.SplitN(line, "|", 2); len(f) == 2 {
				have[strings.ToLower(strings.TrimSpace(f[0]))] = true
			}
		}
		var add []string
		for _, line := range ru.Services {
			f := strings.Split(line, "|")
			if len(f) < 2 || strings.ContainsAny(line, "\r\n") {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(f[0]))
			if name == "" || have[name] {
				continue
			}
			have[name] = true
			add = append(add, line)
		}
		if len(add) > 0 {
			text := strings.TrimRight(string(b), "\r\n") + "\n" + strings.Join(add, "\n") + "\n"
			if os.WriteFile(sitesPath(), []byte(text), 0644) == nil {
				newSvc = len(add)
			}
		}
	}
	for asn, ids := range ru.Presets {
		if asnRe.MatchString(asn) && len(ids) <= 20 {
			for i, id := range ids {
				if !builtinID[id] && !strings.HasPrefix(id, "u-") {
					ids[i] = "u-" + id // стратегии из обновления хранятся с префиксом u-
				}
			}
			remotePresets[strings.ToUpper(asn)] = ids
		}
	}
	msg := fmt.Sprintf("Обновления (%s, от %s): стратегий +%d", src, firstNonEmpty(ru.Updated, "?"), len(added))
	if newSvc > 0 {
		msg += fmt.Sprintf(", новых сервисов +%d", newSvc)
	}
	info("%s", msg)
}
