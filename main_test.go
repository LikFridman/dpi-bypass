package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestValidStrategy(t *testing.T) {
	ok := []Strategy{
		{"a", "x", []string{"--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com"}},
		{"b", "x", []string{"--dpi-desync=fake", "--dpi-desync-fake-tls=0x16030100"}},
	}
	bad := []Strategy{
		{"c", "x", []string{"--wf-raw=@C:\\evil.txt"}},
		{"d", "x", []string{"--dpi-desync-fake-tls=C:/file.bin"}},
		{"e", "x", []string{"--dpi-desync=fake --hostlist=x"}},
		{"f", "x", []string{"--dpi-desync-fake-quic=..\\a"}},
		{"g", "x", nil},
	}
	for _, s := range ok {
		if !validStrategy(s) {
			t.Errorf("должна пройти: %v", s.Args)
		}
	}
	for _, s := range bad {
		if validStrategy(s) {
			t.Errorf("должна быть отклонена: %v", s.Args)
		}
	}
}

// update/update.json из репозитория должен проходить проверку, иначе программа его отбросит
func TestUpdateFileValid(t *testing.T) {
	b, err := os.ReadFile("update/update.json")
	if err != nil {
		t.Skip("нет update/update.json")
	}
	var ru struct {
		Strategies []Strategy `json:"strategies"`
		Services   []string   `json:"services"`
	}
	if err := json.Unmarshal(b, &ru); err != nil {
		t.Fatal(err)
	}
	for _, s := range ru.Strategies {
		if !validStrategy(s) {
			t.Errorf("стратегия %q не проходит проверку", s.ID)
		}
	}
	for _, l := range ru.Services {
		if len(strings.Split(l, "|")) < 2 {
			t.Errorf("неверная строка сервиса: %q", l)
		}
	}
}

func TestDeepCombos(t *testing.T) {
	c := deepCombos()
	if len(c) < 200 {
		t.Fatalf("слишком мало комбинаций: %d", len(c))
	}
	ids := map[string]bool{}
	for _, s := range c {
		if !validStrategy(s) {
			t.Errorf("комбинация не проходит проверку: %v", s.Args)
		}
		if ids[s.ID] {
			t.Errorf("повтор id %s", s.ID)
		}
		ids[s.ID] = true
	}
	t.Logf("комбинаций: %d", len(c))
}
