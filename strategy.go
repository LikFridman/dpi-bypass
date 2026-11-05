package main

import (
	"fmt"
	"regexp"
	"strings"
)

type Strategy struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Args []string `json:"args"` // параметры winws для TCP 443 (TLS)
}

// безопасные параметры winws: только --dpi-desync*, без путей к файлам
var (
	argRe    = regexp.MustCompile(`^--dpi-desync(-[a-z0-9]+)*(=[A-Za-z0-9,._:+=-]+)?$`)
	hexValRe = regexp.MustCompile(`=0x[0-9a-fA-F]+$`)
)

func validStrategy(s Strategy) bool {
	if s.ID == "" || s.Name == "" || len(s.Args) == 0 || len(s.Args) > 12 || len(s.Name) > 80 {
		return false
	}
	for _, a := range s.Args {
		if !argRe.MatchString(a) {
			return false
		}
		name := a
		if i := strings.Index(a, "="); i >= 0 {
			name = a[:i]
		}
		// параметры, которые принимают файл, разрешены только с hex-значением
		if (strings.Contains(name, "-fake-") && name != "--dpi-desync-fake-tls-mod") || strings.HasSuffix(name, "-pattern") {
			if !hexValRe.MatchString(a) {
				return false
			}
		}
	}
	return true
}

// deepCombos генерирует комбинации: способ разбиения x место разреза x обман DPI
func deepCombos() []Strategy {
	positions := []string{"1", "2", "midsld", "sniext+1", "1,midsld", "host+1"}
	foolings := []struct{ name, args string }{
		{"md5sig", "--dpi-desync-fooling=md5sig"},
		{"badseq", "--dpi-desync-fooling=badseq"},
		{"autottl", "--dpi-desync-autottl=2"},
		{"ts", "--dpi-desync-fooling=ts"},
		{"ttl3", "--dpi-desync-ttl=3"},
		{"ttl5", "--dpi-desync-ttl=5"},
		{"datanoack", "--dpi-desync-fooling=datanoack"},
		{"badsum", "--dpi-desync-fooling=badsum"},
	}
	var res []Strategy
	n := 0
	add := func(name string, args ...string) {
		n++
		res = append(res, Strategy{ID: fmt.Sprintf("d%d", n), Name: name, Args: args})
	}
	// без фейков: только разрезание
	for _, mode := range []string{"multisplit", "multidisorder"} {
		for _, pos := range positions {
			add(mode+" "+pos, "--dpi-desync="+mode, "--dpi-desync-split-pos="+pos)
		}
	}
	for _, ovl := range []string{"568", "652", "681"} {
		for _, pos := range []string{"1", "2", "sniext+1"} {
			add("multisplit seqovl="+ovl+" "+pos, "--dpi-desync=multisplit", "--dpi-desync-split-pos="+pos, "--dpi-desync-split-seqovl="+ovl)
		}
	}
	// фейки без разрезания
	for _, f := range foolings {
		add("fake "+f.name, "--dpi-desync=fake", f.args, "--dpi-desync-repeats=6")
		add("fake "+f.name+" (подмена SNI)", "--dpi-desync=fake", f.args, "--dpi-desync-repeats=6", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com")
		add("hostfakesplit "+f.name, "--dpi-desync=hostfakesplit", f.args, "--dpi-desync-repeats=4")
	}
	// фейки + разрезание - основная часть перебора
	for _, mode := range []string{"fake,multidisorder", "fake,multisplit", "fakedsplit", "fakeddisorder", "fake,fakedsplit"} {
		for _, f := range foolings {
			for _, pos := range positions {
				add(mode+" "+pos+" "+f.name, "--dpi-desync="+mode, "--dpi-desync-split-pos="+pos, f.args, "--dpi-desync-repeats=6")
			}
		}
	}
	for _, pos := range positions {
		add("syndata,multisplit "+pos, "--dpi-desync=syndata,multisplit", "--dpi-desync-split-pos="+pos)
	}
	return res
}
