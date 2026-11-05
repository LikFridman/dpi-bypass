package main

import (
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
