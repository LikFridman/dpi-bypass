//go:build windows

package main

// Зашифрованный DNS на Windows. Браузеры и программы спрашивают адреса сайтов у системного DNS,
// а провайдер его подменяет (Instagram, Facebook, Rutracker: «DNS не отвечает или подменён»).
// На время обхода (режим без VPN) программа поднимает DNS-сервер на 127.0.0.1:53, который отвечает
// через DoH (Cloudflare/Google по HTTPS), и указывает его DNS-сервером интернет-адаптеров.
// При выключении обхода настройки адаптеров возвращаются как были; если программа завершилась
// аварийно, они возвращаются при следующем запуске (файл dns-backup.json).

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"dpibypass/doh"
)

var (
	dohMu       sync.Mutex
	dohRes      *doh.Resolver
	dohClosers  []interface{ Close() error }
	dohActive   bool
	pDnsFlush   = syscall.NewLazyDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")
	dnsBackupMu sync.Mutex
)

type dnsBackup struct {
	Index uint32 `json:"index"`
	GUID  string `json:"guid"`
	Name  string `json:"name"`
	V4    string `json:"v4"` // статические DNS до включения ("" - получал от DHCP)
	V6    string `json:"v6"`
}

func dnsBackupPath() string { return filepath.Join(dataDir, "dns-backup.json") }

func regDNS(guid string, v6 bool) string {
	svc := "Tcpip"
	if v6 {
		svc = "Tcpip6"
	}
	return strings.TrimSpace(regStr(`SYSTEM\CurrentControlSet\Services\`+svc+`\Parameters\Interfaces\`+guid, "NameServer"))
}

func netsh(args ...string) error {
	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = hiddenProcAttr()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// setDNS: servers "" - получать от DHCP; иначе список через запятую или пробел
func setDNS(index uint32, v6 bool, servers string) error {
	fam := "ipv4"
	if v6 {
		fam = "ipv6"
	}
	name := fmt.Sprint(index)
	list := strings.FieldsFunc(servers, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	if len(list) == 0 {
		return netsh("interface", fam, "set", "dnsservers", "name="+name, "source=dhcp")
	}
	if err := netsh("interface", fam, "set", "dnsservers", "name="+name, "source=static", "address="+list[0], "register=none", "validate=no"); err != nil {
		return err
	}
	for i, s := range list[1:] {
		netsh("interface", fam, "add", "dnsservers", "name="+name, "address="+s, fmt.Sprintf("index=%d", i+2), "validate=no")
	}
	return nil
}

func flushDNS() { pDnsFlush.Call() }

// restoreDNS возвращает DNS адаптеров из резервной копии (после выключения или аварийного завершения)
func restoreDNS() {
	dnsBackupMu.Lock()
	defer dnsBackupMu.Unlock()
	b, err := os.ReadFile(dnsBackupPath())
	if err != nil {
		return
	}
	var list []dnsBackup
	json.Unmarshal(b, &list)
	ok := true
	for _, a := range list {
		if err := setDNS(a.Index, false, a.V4); err != nil {
			warn("DNS адаптера %s не вернулся: %v", a.Name, err)
			ok = false
		}
		setDNS(a.Index, true, a.V6)
	}
	flushDNS()
	if ok {
		os.Remove(dnsBackupPath())
		if len(list) > 0 {
			info("DNS адаптеров возвращён как был")
		}
	}
}

// dohStart: включить зашифрованный DNS (только режим без VPN и когда VPN не активен)
func dohStart() {
	dohMu.Lock()
	defer dohMu.Unlock()
	if dohActive || settings.NoDoH || runMode != modeNoVPN || curVPN.Active() {
		return
	}
	restoreDNS() // осталось от прошлого запуска
	r := doh.NewFor(settings.DNS, settings.DNSCustom, nil, nil)
	// DoH вообще доступен? (иначе не трогаем систему)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	_, err := r.LookupIP(ctx, "www.google.com")
	cancel()
	if err != nil {
		warn("Зашифрованный DNS недоступен (%v) - оставляю DNS провайдера", shortErr(err))
		return
	}
	var closers []interface{ Close() error }
	for _, addr := range []string{"127.0.0.1:53", "[::1]:53"} {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			if addr == "127.0.0.1:53" {
				warn("Зашифрованный DNS: порт 53 занят (%v) - оставляю DNS провайдера", shortErr(err))
				for _, c := range closers {
					c.Close()
				}
				return
			}
			continue
		}
		go r.ServeUDP(pc)
		closers = append(closers, pc)
		if l, err := net.Listen("tcp", addr); err == nil {
			go r.ServeTCP(l)
			closers = append(closers, l)
		}
	}
	var backup []dnsBackup
	for _, a := range listAdapters() {
		if !a.Gateway || isVPNAdapter(a) || a.GUID == "" {
			continue
		}
		backup = append(backup, dnsBackup{Index: a.Index, GUID: a.GUID, Name: a.Name, V4: regDNS(a.GUID, false), V6: regDNS(a.GUID, true)})
	}
	if len(backup) == 0 {
		for _, c := range closers {
			c.Close()
		}
		return
	}
	dnsBackupMu.Lock()
	bb, _ := json.MarshalIndent(backup, "", "  ")
	os.WriteFile(dnsBackupPath(), bb, 0644)
	dnsBackupMu.Unlock()
	var names []string
	for _, a := range backup {
		// второй адрес - запасной: если программу завершат аварийно, интернет не пропадёт
		// (Windows сразу перейдёт ко второму серверу, а при следующем запуске всё вернётся как было)
		if err := setDNS(a.Index, false, "127.0.0.1,1.1.1.1"); err != nil {
			warn("Зашифрованный DNS: адаптер %s не настроился: %v", a.Name, err)
			continue
		}
		setDNS(a.Index, true, "::1,2606:4700:4700::1111")
		names = append(names, a.Name)
	}
	flushDNS()
	dohRes, dohClosers, dohActive = r, closers, true
	good("Зашифрованный DNS включён (%s): провайдер не подменит адреса сайтов", strings.Join(names, ", "))
}

// dohStop: вернуть DNS адаптеров и остановить локальный сервер
func dohStop() {
	dohMu.Lock()
	defer dohMu.Unlock()
	restoreDNS()
	for _, c := range dohClosers {
		c.Close()
	}
	dohClosers, dohActive = nil, false
}

// dohStats - для отчёта и вкладки DNS
func dohStats() map[string]any {
	prov := settings.DNS
	if prov == "" {
		prov = "auto"
	}
	m := map[string]any{"enabled": !settings.NoDoH, "provider": prov, "custom": settings.DNSCustom, "providers": doh.Providers}
	// не ждём, пока dohStart проверяет серверы (до 8 с) - окно не должно подвисать
	if !dohMu.TryLock() {
		m["active"] = false
		return m
	}
	defer dohMu.Unlock()
	m["active"] = dohActive
	if dohRes != nil {
		m["current"] = dohRes.Current()
		dohRes.Stats.Lock()
		m["queries"], m["cache_hits"], m["failures"], m["last_error"] = dohRes.Stats.Queries, dohRes.Stats.CacheHits, dohRes.Stats.Failures, dohRes.Stats.LastError
		dohRes.Stats.Unlock()
	}
	return m
}

// dohRestart - применить другой сервер DoH, если зашифрованный DNS сейчас работает
func dohRestart() {
	dohMu.Lock()
	act := dohActive
	dohMu.Unlock()
	if act {
		dohStop()
		dohStart()
	}
}
