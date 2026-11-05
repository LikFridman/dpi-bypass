//go:build windows

package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const tgDefaultPort = 1443

var (
	tgProxy      *TGProxy
	tgWorkerHost string // свой Cloudflare Worker (dpi-bypass-data\telegram-worker.txt)
	tgHinted     bool

	//go:embed cloudflare-worker.js
	workerJS string
)

func tgWorkerFile() string { return filepath.Join(dataDir, "telegram-worker.txt") }
func tgWorkerJS() string   { return filepath.Join(dataDir, "telegram-worker.js") }

// loadTGWorker читает адрес Worker'а и кладёт рядом код для него
func loadTGWorker() {
	os.WriteFile(tgWorkerJS(), []byte(workerJS), 0644)
	b, err := os.ReadFile(tgWorkerFile())
	if err != nil {
		os.WriteFile(tgWorkerFile(), []byte("# Сюда одной строкой адрес своего Cloudflare Worker, например: tg.myname.workers.dev\n# Как создать - в начале файла telegram-worker.js\n"), 0644)
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(strings.TrimPrefix(line, "https://"), "wss://")
		if i := strings.IndexAny(line, "/ "); i >= 0 {
			line = line[:i]
		}
		tgWorkerHost = line
		return
	}
}

func tgSecretFile() string { return filepath.Join(dataDir, "telegram-secret.txt") }
func tgPortFile() string   { return filepath.Join(dataDir, "telegram-port.txt") }

// tgSecret возвращает постоянный секрет (чтобы ссылку не нужно было добавлять заново)
func tgSecret() (secret []byte, fresh bool) {
	if b, err := os.ReadFile(tgSecretFile()); err == nil {
		if s, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(s) == 16 {
			return s, false
		}
	}
	secret = make([]byte, 16)
	rand.Read(secret)
	os.WriteFile(tgSecretFile(), []byte(hex.EncodeToString(secret)), 0644)
	return secret, true
}

func tgLink(port int, secret []byte) string {
	return fmt.Sprintf("tg://proxy?server=127.0.0.1&port=%d&secret=dd%s", port, hex.EncodeToString(secret))
}

func telegramInstalled() bool {
	c := exec.Command("reg", "query", `HKCR\tg`)
	c.SysProcAttr = hiddenProcAttr()
	return c.Run() == nil
}

func openURL(u string) error {
	c := exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	c.SysProcAttr = hiddenProcAttr()
	return c.Start()
}

// tgRoutes - способы связи с Telegram по порядку (пересчитываются для каждого соединения)
func tgRoutes(px *TGProxy) []TGRoute {
	base := px.BaseRoutes() // WebSocket напрямую, TCP напрямую
	r := []TGRoute{base[0]}
	if tgWorkerHost != "" {
		r = append(r, px.WorkerRoute(tgWorkerHost))
	}
	r = append(r, base[1])
	if runMode == modeNoVPN {
		return r
	}
	for _, s := range vpnSocks() {
		r = append(r, SocksRoute("через VPN (SOCKS5)", s))
	}
	return r
}

func tgHint(ipBlocked bool) {
	if ipBlocked {
		warn("IP-адреса Telegram у твоего провайдера заблокированы - обход DPI их не откроет.")
	} else {
		warn("Telegram не удалось подключить ни одним способом.")
	}
	say("      Что сработает:")
	if socks := vpnSocks(); len(socks) > 0 {
		say("       - VPN уже найден (%s) - Telegram сам пойдёт через него, если остальное не выйдет.", strings.Join(socks, ", "))
	} else {
		say("       - включить VPN (Happ и т.п.): программа найдёт его и пустит Telegram через него;")
	}
	say("       - свой бесплатный Cloudflare Worker: инструкция в %s,", tgWorkerJS())
	say("         адрес вписать в %s и перезапустить программу.", tgWorkerFile())
}

// startTelegram запускает локальный прокси для Telegram Desktop.
func startTelegram(openLink bool, cfg *Config) {
	title("Telegram")
	secret, fresh := tgSecret()
	px := &TGProxy{
		Secret: secret,
		Resolve: func(host string) net.IP {
			if ii, ok := resolve(host); ok {
				return ii.IP
			}
			return nil
		},
		Log: func(format string, a ...any) { info("%s %s", ts(), fmt.Sprintf(format, a...)) },
	}
	px.Routes = func() []TGRoute { return tgRoutes(px) }

	port := tgDefaultPort
	if b, err := os.ReadFile(tgPortFile()); err == nil {
		if p, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && p > 0 {
			port = p
		}
	}
	var err error
	for try := 0; try < 10; try++ {
		if err = px.Listen(fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			break
		}
		port++
		fresh = true // порт поменялся - ссылку нужно добавить заново
	}
	if err != nil {
		bad("Не удалось запустить прокси для Telegram: %v", err)
		return
	}
	os.WriteFile(tgPortFile(), []byte(strconv.Itoa(port)), 0644)
	tgProxy = px

	link := tgLink(port, secret)
	good("Прокси для Telegram запущен на 127.0.0.1:%d", port)
	say("      Telegram пойдёт через WebSocket к web.telegram.org - его маскирует обход DPI.")
	say("      Ссылка для подключения (Telegram Desktop):")
	say("      %s", col(cBold, link))
	if (fresh || openLink) && telegramInstalled() {
		if openURL(link) == nil {
			say("%s", col(cGray, "      Открыл ссылку - в Telegram нажми «Подключиться» / «Enable»."))
		}
	} else {
		say("%s", col(cGray, "      Добавить вручную: Telegram -> Настройки -> Продвинутые -> Тип соединения -> Прокси -> MTProto,"))
		say("%s", col(cGray, fmt.Sprintf("      сервер 127.0.0.1, порт %d, секрет dd%s", port, hex.EncodeToString(secret))))
	}
	say("%s", col(cGray, "      Telegram работает только пока открыто это окно. Звонки через прокси Telegram не поддерживает."))
	if tgWorkerHost != "" {
		info("Cloudflare Worker для Telegram: %s", tgWorkerHost)
	}
	if _, blocked := cfg.Unfixable["Telegram"]; blocked && tgWorkerHost == "" && len(vpnSocks()) == 0 {
		tgHint(true)
		tgHinted = true
	}
}

// tgWatch вызывается сторожем: подсказать, если Telegram никак не подключается
func tgWatch() {
	if tgProxy == nil || tgHinted {
		return
	}
	if tgProxy.AllFailed() >= 3 {
		tgHint(false)
		tgHinted = true
	}
}

func tgStatusLine() string {
	if tgProxy == nil {
		return ""
	}
	active, total, ws, tcp, failed := tgProxy.Stats()
	if total == 0 {
		return ""
	}
	return fmt.Sprintf("Telegram: соединений %d (сейчас %d) - WebSocket %d, напрямую %d, ошибок %d", total, active, ws, tcp, failed)
}
