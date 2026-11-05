//go:build windows

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

type Service struct {
	Name    string
	Probes  []string // хосты, на которых проверяем доступность
	Domains []string // домены, к которым применяется обход
}

const defaultSites = `# Список сервисов для проверки и обхода.
# Формат строки:  Название | хосты для проверки | домены для обхода (с поддоменами)
# Строки с # игнорируются. После правки запусти dpi-bypass.exe auto

YouTube   | www.youtube.com i.ytimg.com redirector.googlevideo.com | youtube.com googlevideo.com ytimg.com ggpht.com youtu.be youtubei.googleapis.com youtube-nocookie.com ytimg.l.google.com
Discord   | discord.com gateway.discord.gg cdn.discordapp.com | discord.com discord.gg discordapp.com discordapp.net discord.media discordcdn.com discord.dev discord.app
Instagram | www.instagram.com | instagram.com cdninstagram.com
Facebook  | www.facebook.com | facebook.com fbcdn.net fb.com
X/Twitter | x.com abs.twimg.com | x.com twitter.com twimg.com t.co
Rutracker | rutracker.org | rutracker.org rutracker.cc
LinkedIn  | www.linkedin.com | linkedin.com licdn.com
Telegram  | web.telegram.org telegram.org | telegram.org t.me telegram.me telesco.pe tdesktop.com
`

const oldTelegramLine = "Telegram  | web.telegram.org telegram.org | telegram.org t.me telegram.me\n"

func sitesPath() string { return filepath.Join(dataDir, "sites.txt") }

func loadServices() ([]Service, error) {
	p := sitesPath()
	if _, err := os.Stat(p); os.IsNotExist(err) {
		if err := os.WriteFile(p, []byte(defaultSites), 0644); err != nil {
			return nil, err
		}
	}
	// обновить строку Telegram из версии 1.0
	if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), oldTelegramLine) {
		os.WriteFile(p, []byte(strings.Replace(string(b), oldTelegramLine, "Telegram  | web.telegram.org telegram.org | telegram.org t.me telegram.me telesco.pe tdesktop.com\n", 1)), 0644)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Service
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\uFEFF"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		s := Service{Name: strings.TrimSpace(parts[0]), Probes: strings.Fields(parts[1])}
		if len(parts) >= 3 {
			s.Domains = strings.Fields(parts[2])
		}
		if len(s.Domains) == 0 {
			s.Domains = s.Probes
		}
		if s.Name != "" && len(s.Probes) > 0 {
			out = append(out, s)
		}
	}
	return out, sc.Err()
}
