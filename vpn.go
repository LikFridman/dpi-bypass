//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// ---------- известные VPN/прокси-клиенты ----------

var vpnProcNames = []struct{ prefix, name string }{
	{"happ", "Happ"},
	{"v2rayn", "v2rayN"},
	{"v2ray", "V2Ray"},
	{"xray", "Xray"},
	{"sing-box", "sing-box"},
	{"singbox", "sing-box"},
	{"nekoray", "NekoRay"},
	{"nekobox", "NekoBox"},
	{"throne", "Throne"},
	{"hiddify", "Hiddify"},
	{"karing", "Karing"},
	{"clash", "Clash"},
	{"mihomo", "Mihomo"},
	{"flclash", "FlClash"},
	{"hysteria", "Hysteria"},
	{"tun2socks", "tun2socks"},
	{"amneziavpn", "AmneziaVPN"},
	{"amneziawg", "AmneziaWG"},
	{"wireguard", "WireGuard"},
	{"openvpn", "OpenVPN"},
	{"outline", "Outline"},
	{"warp-svc", "Cloudflare WARP"},
	{"protonvpn", "Proton VPN"},
	{"nordvpn", "NordVPN"},
	{"expressvpn", "ExpressVPN"},
	{"adguardvpn", "AdGuard VPN"},
	{"windscribe", "Windscribe"},
	{"psiphon", "Psiphon"},
	{"lantern", "Lantern"},
	{"invizible", "InviZible"},
	{"streisand", "Streisand"},
	{"v2raytun", "v2RayTun"},
}

// ключевые слова в названии/описании сетевого адаптера VPN
var vpnAdapterWords = []string{"wintun", "tun", "tap-windows", "tap-", "wireguard", "amnezia", "happ",
	"sing-box", "singbox", "xray", "v2ray", "clash", "mihomo", "meta", "nekoray", "hiddify", "outline",
	"openvpn", "warp", "vpn", "throne", "karing", "tunnel"}

// виртуальные адаптеры, которые не являются VPN
var notVPNAdapterWords = []string{"hyper-v", "virtualbox", "vmware", "loopback", "bluetooth", "teredo",
	"isatap", "6to4", "kernel debug", "npcap", "wan miniport", "docker", "wsl"}

type VPNState struct {
	Procs      []string // имена найденных VPN-клиентов
	procPIDs   map[string]bool
	TunNames   []string // активные VPN-адаптеры
	FullTunnel bool     // весь интернет идёт через VPN-адаптер
	PhysIdx    uint32   // индекс физического адаптера (Ethernet/Wi-Fi)
	PhysName   string
	SysProxy   string // системный прокси, если включён
	ServerIPs  []string
	Socks      []string // локальные SOCKS5-порты VPN-клиента (127.0.0.1:10808 и т.п.)
}

func (s VPNState) Active() bool { return len(s.Procs) > 0 || len(s.TunNames) > 0 }

// UseIface - нужно ли привязывать обход к физическому адаптеру
func (s VPNState) UseIface() bool { return len(s.TunNames) > 0 && s.PhysIdx != 0 }

func (s VPNState) Key() string {
	return fmt.Sprintf("%v|%v|%v|%d|%s|%v", s.Procs, s.TunNames, s.FullTunnel, s.PhysIdx, s.SysProxy, s.ServerIPs)
}

func (s VPNState) Mode() string {
	switch {
	case s.FullTunnel:
		return "TUN, весь трафик через VPN"
	case len(s.TunNames) > 0:
		return "TUN, раздельная маршрутизация"
	case s.SysProxy != "":
		return "системный прокси " + s.SysProxy
	default:
		return "фоновый режим / только для отдельных программ"
	}
}

// ---------- адаптеры ----------

type adapter struct {
	Index   uint32
	Name    string // понятное имя ("Ethernet", "Wi-Fi")
	Desc    string
	Gateway bool
	IPs     []string
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func listAdapters() []adapter {
	size := uint32(16 * 1024)
	var buf []byte
	for i := 0; i < 3; i++ {
		buf = make([]byte, size)
		err := syscall.GetAdaptersInfo((*syscall.IpAdapterInfo)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != syscall.ERROR_BUFFER_OVERFLOW {
			return nil
		}
	}
	names := map[int]string{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			names[i.Index] = i.Name
		}
	}
	var out []adapter
	for ai := (*syscall.IpAdapterInfo)(unsafe.Pointer(&buf[0])); ai != nil; ai = ai.Next {
		a := adapter{Index: ai.Index, Desc: cstr(ai.Description[:]), Name: names[int(ai.Index)]}
		for g := &ai.GatewayList; g != nil; g = g.Next {
			if s := cstr(g.IpAddress.String[:]); s != "" && s != "0.0.0.0" {
				a.Gateway = true
			}
		}
		for ip := &ai.IpAddressList; ip != nil; ip = ip.Next {
			if s := cstr(ip.IpAddress.String[:]); s != "" && s != "0.0.0.0" && !strings.HasPrefix(s, "169.254.") {
				a.IPs = append(a.IPs, s)
			}
		}
		out = append(out, a)
	}
	return out
}

func containsAny(s string, words []string) bool {
	s = strings.ToLower(s)
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func isVPNAdapter(a adapter) bool {
	txt := a.Name + " " + a.Desc
	if containsAny(txt, notVPNAdapterWords) {
		return false
	}
	return containsAny(txt, vpnAdapterWords)
}

var procGetBestInterface = syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetBestInterface")

func bestInterface(ip string) uint32 {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return 0
	}
	var idx uint32
	r, _, _ := procGetBestInterface.Call(uintptr(binary.LittleEndian.Uint32(p)), uintptr(unsafe.Pointer(&idx)))
	if r != 0 {
		return 0
	}
	return idx
}

// ---------- системный прокси ----------

func systemProxy() string {
	c := exec.Command("reg", "query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	c.SysProcAttr = hiddenProcAttr()
	out, err := c.Output()
	if err != nil {
		return ""
	}
	enabled, server := false, ""
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		switch f[0] {
		case "ProxyEnable":
			enabled = f[len(f)-1] == "0x1"
		case "ProxyServer":
			server = f[len(f)-1]
		}
	}
	if enabled {
		return server
	}
	return ""
}

// ---------- процессы и их соединения ----------

func vpnProcesses() (names []string, pids map[string]bool) {
	pids = map[string]bool{}
	c := exec.Command("tasklist", "/FO", "CSV", "/NH")
	c.SysProcAttr = hiddenProcAttr()
	out, err := c.Output()
	if err != nil {
		return nil, pids
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, `","`)
		if len(f) < 2 {
			continue
		}
		img := strings.ToLower(strings.Trim(f[0], `" `))
		pid := strings.Trim(f[1], `" `)
		for _, v := range vpnProcNames {
			if strings.HasPrefix(img, v.prefix) {
				pids[pid] = true
				if !seen[v.name] {
					seen[v.name] = true
					names = append(names, v.name)
				}
				break
			}
		}
	}
	return names, pids
}

// vpnServerIPs - внешние адреса, к которым подключены VPN-процессы (это серверы VPN)
func vpnServerIPs(pids map[string]bool) []string {
	if len(pids) == 0 {
		return nil
	}
	c := exec.Command("netstat", "-ano", "-p", "TCP")
	c.SysProcAttr = hiddenProcAttr()
	out, err := c.Output()
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "TCP" || !pids[f[4]] {
			continue
		}
		host, _, err := net.SplitHostPort(f[2])
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); usableIP(ip) {
			set[ip.String()] = true
		}
	}
	var ips []string
	for ip := range set {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips
}

// vpnLocalSocks ищет локальные SOCKS5-порты, которые слушает VPN-клиент.
func vpnLocalSocks(pids map[string]bool) []string {
	if len(pids) == 0 {
		return nil
	}
	c := exec.Command("netstat", "-ano", "-p", "TCP")
	c.SysProcAttr = hiddenProcAttr()
	out, err := c.Output()
	if err != nil {
		return nil
	}
	var res []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "TCP" || f[3] != "LISTENING" || !pids[f[4]] {
			continue
		}
		host, port, err := net.SplitHostPort(f[1])
		if err != nil || (host != "127.0.0.1" && host != "0.0.0.0") {
			continue
		}
		addr := "127.0.0.1:" + port
		if seen[addr] || len(seen) >= 8 {
			continue
		}
		seen[addr] = true
		if IsSocks5(addr) {
			res = append(res, addr)
		}
	}
	return res
}

// ---------- общий детектор ----------

func detectVPN() VPNState {
	var s VPNState
	s.Procs, s.procPIDs = vpnProcesses()
	s.SysProxy = systemProxy()

	ads := listAdapters()
	byIdx := map[uint32]adapter{}
	var phys []adapter
	for _, a := range ads {
		byIdx[a.Index] = a
		if isVPNAdapter(a) {
			if len(a.IPs) > 0 {
				s.TunNames = append(s.TunNames, firstNonEmpty(a.Name, a.Desc))
			}
		} else if a.Gateway && !containsAny(a.Name+" "+a.Desc, notVPNAdapterWords) {
			phys = append(phys, a)
		}
	}
	if best, ok := byIdx[bestInterface("1.1.1.1")]; ok {
		if isVPNAdapter(best) {
			s.FullTunnel = true
		} else {
			s.PhysIdx, s.PhysName = best.Index, firstNonEmpty(best.Name, best.Desc)
		}
	}
	if s.PhysIdx == 0 && len(phys) > 0 {
		s.PhysIdx, s.PhysName = phys[0].Index, firstNonEmpty(phys[0].Name, phys[0].Desc)
	}
	s.ServerIPs = vpnServerIPs(s.procPIDs)
	s.Socks = vpnLocalSocks(s.procPIDs)
	return s
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

// ---------- применение ----------

// applyVPN настраивает проверки (привязка к физическому адаптеру) и сбрасывает кэш DNS.
func applyVPN(s VPNState) {
	if s.UseIface() {
		bindIfIdx.Store(s.PhysIdx)
	} else {
		bindIfIdx.Store(0)
	}
	skipSysDNS.Store(len(s.TunNames) > 0)
	vpnSocksV.Store(append([]string{}, s.Socks...))
	ipCacheMu.Lock()
	ipCache = map[string]ipInfo{}
	ipCacheMu.Unlock()
}

var vpnSocksV atomic.Value // []string - читается из горутин прокси Telegram

func vpnSocks() []string {
	v, _ := vpnSocksV.Load().([]string)
	return v
}

func vpnExcludeFile() string { return filepath.Join(dataDir, "lists", "vpn-servers.txt") }

// writeVPNExclude записывает адреса VPN-серверов, чтобы winws не трогал соединения самого VPN.
func writeVPNExclude(s VPNState) string {
	if len(s.ServerIPs) == 0 {
		return ""
	}
	p := vpnExcludeFile()
	os.MkdirAll(filepath.Dir(p), 0755)
	if os.WriteFile(p, []byte(strings.Join(s.ServerIPs, "\n")+"\n"), 0644) != nil {
		return ""
	}
	return p
}

func printVPN(s VPNState) {
	if !s.Active() {
		info("VPN не обнаружен.")
		return
	}
	name := strings.Join(s.Procs, ", ")
	if name == "" {
		name = "VPN-адаптер " + strings.Join(s.TunNames, ", ")
	}
	warn("Обнаружен VPN: %s (%s)", col(cBold, name), s.Mode())
	if s.UseIface() {
		say("      Обход работает только на физическом адаптере «%s» (#%d), трафик внутри VPN не трогаю.", s.PhysName, s.PhysIdx)
	}
	if len(s.Socks) > 0 {
		say("      Локальный SOCKS5 VPN: %s - через него может пойти Telegram, если иначе не выйдет.", strings.Join(s.Socks, ", "))
	}
	if len(s.ServerIPs) > 0 {
		say("      Соединения с сервером VPN (%s) исключены из обработки.", strings.Join(s.ServerIPs, ", "))
	}
	switch {
	case s.FullTunnel:
		say("%s", col(cGray, "      Сейчас весь трафик идёт через VPN. Чтобы YouTube/Discord шли напрямую через обход,"))
		say("%s", col(cGray, "      добавь их в «Direct» (напрямую) в маршрутизации VPN-клиента. Готовый список доменов:"))
		say("%s", col(cGray, "      "+directListFile()))
	case len(s.TunNames) == 0 && s.SysProxy != "":
		say("%s", col(cGray, "      Браузер ходит через прокси VPN. Программы без прокси (Discord, игры) будут"))
		say("%s", col(cGray, "      работать через обход. Чтобы и браузер шёл напрямую - добавь сайты в «Direct»: "+directListFile()))
	}
}

func directListFile() string { return filepath.Join(dataDir, "vpn-direct-domains.txt") }

// writeDirectList сохраняет домены, которые открываются обходом, - для правил Direct в Happ и т.п.
func writeDirectList(cfg *Config, svcs []Service) {
	ok := map[string]bool{}
	for _, n := range cfg.Expected {
		ok[n] = true
	}
	var b strings.Builder
	b.WriteString("# Домены, которые открываются через dpi-bypass без VPN.\n")
	b.WriteString("# В Happ: Настройки маршрутизации -> Direct (напрямую) -> вставить список.\n")
	b.WriteString("# Формат для Xray/Happ: domain:example.com\n\n")
	for _, s := range svcs {
		if !ok[s.Name] {
			continue
		}
		b.WriteString("# " + s.Name + "\n")
		for _, d := range s.Domains {
			b.WriteString("domain:" + d + "\n")
		}
	}
	os.WriteFile(directListFile(), []byte(b.String()), 0644)
}

func ifaceArg(s VPNState) []string {
	if !s.UseIface() {
		return nil
	}
	return []string{"--wf-iface=" + strconv.FormatUint(uint64(s.PhysIdx), 10)}
}
