//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

var colorsOn bool

// out - всё, что видно в окне; копия без цветов пишется в dpi-bypass-data\log.txt
var out io.Writer = os.Stdout

type logWriter struct{ f *os.File }

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

func (l logWriter) Write(p []byte) (int, error) {
	l.f.Write(ansiRe.ReplaceAll(p, nil))
	return len(p), nil
}

// initLog открывает лог (старый переименовывается в log-old.txt)
// safeWriter не даёт ошибке одного вывода (например, нет консоли) остановить остальные
type safeWriter struct{ w io.Writer }

func (s safeWriter) Write(p []byte) (int, error) {
	if s.w != nil {
		s.w.Write(p)
	}
	return len(p), nil
}

var (
	logFileWriter io.Writer = io.Discard
	logPath       string
)

func initLog(path string) {
	logPath = path
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		os.Rename(path, strings.TrimSuffix(path, ".txt")+"-old.txt")
	}
	f, err := os.Create(path)
	if err != nil {
		return
	}
	fmt.Fprintf(f, "dpi-bypass %s, запуск %s\n", version, time.Now().Format("02.01.2006 15:04:05"))
	logFileWriter = logWriter{f}
	out = io.MultiWriter(safeWriter{os.Stdout}, safeWriter{logFileWriter})
}

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

func say(format string, a ...any) { fmt.Fprintf(out, format+"\n", a...) }
func info(format string, a ...any) {
	fmt.Fprintf(out, "%s %s\n", col(cCyan, "[i]"), fmt.Sprintf(format, a...))
}
func good(format string, a ...any) {
	fmt.Fprintf(out, "%s %s\n", col(cGreen, "[+]"), fmt.Sprintf(format, a...))
}
func bad(format string, a ...any) {
	fmt.Fprintf(out, "%s %s\n", col(cRed, "[-]"), fmt.Sprintf(format, a...))
}
func warn(format string, a ...any) {
	fmt.Fprintf(out, "%s %s\n", col(cYellow, "[!]"), fmt.Sprintf(format, a...))
}
func title(format string, a ...any) {
	fmt.Fprintf(out, "\n%s\n", col(cBold+cCyan, "== "+fmt.Sprintf(format, a...)+" =="))
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
	if guiMode {
		return
	}
	fmt.Fprint(out, "\nНажми Enter, чтобы закрыть...")
	readLine()
}

func banner() {
	if guiMode {
		say("dpi-bypass %s - локальный обход DPI на базе winws (zapret)", version)
		return
	}
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

  (без команды)  окно с кнопками
  console        меню в консоли
  1 | on         включить обход (VPN будет выключен)
  2 | vpn        включить обход вместе с VPN
  3 | off        выключить обход и завершить всё
  4 | check      диагностика: сайты, VPN, сеть
  auto           заново перебрать стратегии и запустить
  tune           подобрать стратегии для новых сайтов из автосписка
  scan [сайт]    глубокая проверка (сотни комбинаций, долго)
  update         проверить и установить новую версию
  telegram       запустить и снова открыть ссылку прокси для Telegram
  reset          удалить сохранённые настройки

Список проверяемых сайтов: dpi-bypass-data\sites.txt (можно редактировать).`)
}
