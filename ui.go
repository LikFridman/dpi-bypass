//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

var colorsOn bool

const (
	cReset  = "\x1b[0m"
	cRed    = "\x1b[91m"
	cGreen  = "\x1b[92m"
	cYellow = "\x1b[93m"
	cCyan   = "\x1b[96m"
	cGray   = "\x1b[90m"
	cBold   = "\x1b[1m"
)

func col(c, s string) string {
	if !colorsOn {
		return s
	}
	return c + s + cReset
}

func ts() string { return col(cGray, time.Now().Format("15:04:05")) }

func say(format string, a ...any) { fmt.Printf(format+"\n", a...) }
func info(format string, a ...any) {
	fmt.Printf("%s %s\n", col(cCyan, "[i]"), fmt.Sprintf(format, a...))
}
func good(format string, a ...any) {
	fmt.Printf("%s %s\n", col(cGreen, "[+]"), fmt.Sprintf(format, a...))
}
func bad(format string, a ...any) { fmt.Printf("%s %s\n", col(cRed, "[-]"), fmt.Sprintf(format, a...)) }
func warn(format string, a ...any) {
	fmt.Printf("%s %s\n", col(cYellow, "[!]"), fmt.Sprintf(format, a...))
}
func title(format string, a ...any) {
	fmt.Printf("\n%s\n", col(cBold+cCyan, "== "+fmt.Sprintf(format, a...)+" =="))
}

func mark(ok bool) string {
	if ok {
		return col(cGreen, "+")
	}
	return col(cRed, "-")
}

func pad(s string, n int) string {
	r := []rune(s)
	if len(r) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(r))
}

func pause() {
	fmt.Print("\nНажми Enter, чтобы закрыть...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func banner() {
	say(col(cBold+cCyan, `
  ____  ____ ___   ____
 |  _ \|  _ \_ _| | __ ) _   _ _ __   __ _ ___ ___
 | | | | |_) | |  |  _ \| | | | '_ \ / _' / __/ __|
 | |_| |  __/| |  | |_) | |_| | |_) | (_| \__ \__ \
 |____/|_|  |___| |____/ \__, | .__/ \__,_|___/___/
                         |___/|_|   v`+version))
	say(col(cGray, "  локальный обход DPI на базе winws (zapret)\n"))
}

func usage() {
	say(`Использование: dpi-bypass.exe [команда]

  (без команды)  подобрать обход (или взять сохранённый) и держать его включённым
  auto           заново перебрать все стратегии и запустить
  check          только диагностика: что и как заблокировано
  telegram       то же, что без команды, но снова открыть ссылку прокси для Telegram
  stop           остановить winws, если он остался запущен
  reset          удалить сохранённые настройки

Список проверяемых сайтов: dpi-bypass-data\sites.txt (можно редактировать).`)
}
