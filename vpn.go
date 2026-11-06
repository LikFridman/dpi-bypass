//go:build windows

package main

import (
	"bytes"
	"dpibypass/tg"
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
	"isatap", "6to4", "kernel debug", "npcap", "wan miniport", "docker", "wsl", "vethernet", "wi-fi direct",
	"hosted network", "radmin", "hamachi", "zerotier", "tailscale", "parallels"}

// по папке программы узнаём только эти клиенты (у остальных названия слишком общие)
var vpnPathWords = map[string]bool{"happ": true, "v2rayn": true, "nekoray": true, "nekobox": true, "hiddify": true,
	"amneziavpn": true, "amneziawg": true, "sing-box": true, "singbox": true, "xray": true, "v2ray": true,
	"mihomo": true, "flclash": true, "karing": true, "invizible": true, "streisand": true, "v2raytun": true}

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
	GUID    string // {....} - имя адаптера в реестре
	Type    uint32 // 6 Ethernet, 71 Wi-Fi, 23 PPP (PPPoE)
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
		a := adapter{Index: ai.Index, Type: ai.Type, Desc: cstr(ai.Description[:]), Name: names[int(ai.Index)], GUID: cstr(ai.AdapterName[:])}
		for g := &ai.GatewayList; g != nil; g = g.Next {
			if s := cstr(g.IpAddress.String[:]); s != "" && s != "0.0.0.0" {
				a.Gateway = true
			}
		}
		if isPPPoE(a) { // PPPoE: шлюза в списке нет, но это настоящий интернет
			a.Gateway = true
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

// isPPPoE - высокоскоростное подключение провайдера (не VPN)
func isPPPoE(a adapter) bool {
	return a.Type == 23 && strings.Contains(strings.ToLower(a.Desc), "pppoe")
}

func isVPNAdapter(a adapter) bool {
	if isPPPoE(a) {
		return false
	}
	if a.Type == 23 { // встроенный VPN Windows: L2TP/PPTP/SSTP/IKEv2
		return true
	}
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

// ---------- процессы (WinAPI, без tasklist/netstat - они зависят от языка Windows) ----------

type procInfo struct {
	PID  uint32
	Exe  string // имя файла, например happ.exe
	Path string // полный путь (если удалось узнать)
}

var procQueryFullName = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")

func processPath(pid uint32) string {
	h, err := syscall.OpenProcess(0x1000, false, pid) // PROCESS_QUERY_LIMITED_INFORMATION
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	r, _, _ := procQueryFullName.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}

func listProcesses() []procInfo {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer syscall.CloseHandle(snap)
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []procInfo
	for err = syscall.Process32First(snap, &e); err == nil; err = syscall.Process32Next(snap, &e) {
		out = append(out, procInfo{PID: e.ProcessID, Exe: syscall.UTF16ToString(e.ExeFile[:])})
	}
	return out
}

// vpnClientName - название VPN-клиента по имени файла или пути (папка Happ, v2rayN и т.д.)
func vpnClientName(p procInfo) string {
	exe := strings.ToLower(p.Exe)
	for _, v := range vpnProcNames {
		if strings.HasPrefix(exe, v.prefix) {
			return v.name
		}
	}
	if p.Path != "" {
		// ядро может называться как угодно (core.exe), но лежит в папке клиента
		dir := strings.ToLower(filepath.Dir(p.Path))
		for _, v := range vpnProcNames {
			if vpnPathWords[v.prefix] && strings.Contains(dir, v.prefix) {
				return v.name
			}
		}
	}
	return ""
}

// ---------- таблица TCP-соединений ----------

type tcpRow struct {
	State      uint32 // 2 - LISTEN, 5 - ESTABLISHED
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	PID        uint32
}

var procGetExtendedTcpTable = syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

func tcpTable() []tcpRow {
	size := uint32(64 * 1024)
	var buf []byte
	for i := 0; i < 4; i++ {
		buf = make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, syscall.AF_INET, 5, 0) // TCP_TABLE_OWNER_PID_ALL
		if r == 0 {
			break
		}
		if r != 122 { // ERROR_INSUFFICIENT_BUFFER
			return nil
		}
		size += 16 * 1024
	}
	n := binary.LittleEndian.Uint32(buf[:4])
	var rows []tcpRow
	for i := uint32(0); i < n; i++ {
		o := 4 + int(i)*24
		if o+24 > len(buf) {
			break
		}
		b := buf[o : o+24]
		port := func(v uint32) int { return int(uint16(v)>>8 | uint16(v)<<8) }
		rows = append(rows, tcpRow{
			State:      binary.LittleEndian.Uint32(b[0:]),
			LocalIP:    net.IPv4(b[4], b[5], b[6], b[7]),
			LocalPort:  port(binary.LittleEndian.Uint32(b[8:])),
			RemoteIP:   net.IPv4(b[12], b[13], b[14], b[15]),
			RemotePort: port(binary.LittleEndian.Uint32(b[16:])),
			PID:        binary.LittleEndian.Uint32(b[20:]),
		})
	}
	return rows
}

// ---------- общий детектор ----------

func detectVPN() VPNState {
	var s VPNState
	s.procPIDs = map[string]bool{}
	pids := map[uint32]string{} // pid -> клиент
	exeByPID := map[uint32]string{}
	seen := map[string]bool{}
	for _, p := range listProcesses() {
		exeByPID[p.PID] = p.Exe
		name := vpnClientName(p)
		if name == "" && p.PID > 4 {
			if exe := strings.ToLower(p.Exe); exe != "svchost.exe" && exe != "explorer.exe" {
				p.Path = processPath(p.PID)
				if strings.Contains(strings.ToLower(p.Path), `\program files`) || strings.Contains(strings.ToLower(p.Path), `\appdata\`) {
					name = vpnClientName(p)
				}
			}
		}
		if name == "" {
			continue
		}
		pids[p.PID] = name
		s.procPIDs[fmt.Sprint(p.PID)] = true
		if !seen[name] {
			seen[name] = true
			s.Procs = append(s.Procs, name)
		}
	}

	s.SysProxy = systemProxy()
	rows := tcpTable()

	// системный прокси на 127.0.0.1 - его держит какой-то прокси-клиент; считаем его VPN
	if host, port, err := net.SplitHostPort(strings.TrimPrefix(firstProxy(s.SysProxy), "http://")); err == nil &&
		(host == "127.0.0.1" || strings.EqualFold(host, "localhost")) {
		for _, r := range rows {
			if r.State == 2 && fmt.Sprint(r.LocalPort) == port {
				if _, ok := pids[r.PID]; !ok && r.PID > 4 {
					name := "прокси-клиент " + exeByPID[r.PID]
					pids[r.PID] = name
					s.procPIDs[fmt.Sprint(r.PID)] = true
					s.Procs = append(s.Procs, name)
				}
				break
			}
		}
	}

	// адаптеры и маршрут по умолчанию
	ads := listAdapters()
	byIdx := map[uint32]adapter{}
	var phys []adapter
	tun := map[uint32]bool{}
	for _, a := range ads {
		byIdx[a.Index] = a
		virtualOK := !containsAny(a.Name+" "+a.Desc, notVPNAdapterWords)
		switch {
		case isVPNAdapter(a) && len(a.IPs) > 0:
			tun[a.Index] = true
		case a.Gateway && (virtualOK || isPPPoE(a)):
			phys = append(phys, a)
		case len(s.Procs) > 0 && !a.Gateway && len(a.IPs) > 0 && virtualOK:
			// VPN-клиент запущен и есть адаптер без шлюза - почти наверняка его TUN
			tun[a.Index] = true
		}
	}
	bi := bestInterface("1.1.1.1")
	if best, ok := byIdx[bi]; ok {
		if tun[bi] || (!best.Gateway && len(s.Procs) > 0) {
			s.FullTunnel = true
			tun[bi] = true
		} else {
			s.PhysIdx, s.PhysName = best.Index, firstNonEmpty(best.Name, best.Desc)
		}
	} else if bi != 0 && len(s.Procs) > 0 {
		// интерфейса нет в списке IPv4-адаптеров - это виртуальный туннель
		s.FullTunnel = true
		tun[bi] = true
	}
	if s.PhysIdx == 0 && len(phys) > 0 {
		s.PhysIdx, s.PhysName = phys[0].Index, firstNonEmpty(phys[0].Name, phys[0].Desc)
	}
	for idx := range tun {
		name := firstNonEmpty(byIdx[idx].Name, byIdx[idx].Desc)
		if name == "" {
			if ifc, err := net.InterfaceByIndex(int(idx)); err == nil {
				name = ifc.Name
			}
		}
		s.TunNames = append(s.TunNames, firstNonEmpty(name, fmt.Sprintf("#%d", idx)))
	}
	sort.Strings(s.TunNames)

	// серверы VPN (внешние адреса соединений VPN-процессов) и локальные SOCKS5
	ipset := map[string]bool{}
	sockSeen := map[int]bool{}
	for _, r := range rows {
		if _, ok := pids[r.PID]; !ok {
			continue
		}
		switch r.State {
		case 5:
			if usableIP(r.RemoteIP) {
				ipset[r.RemoteIP.String()] = true
			}
		case 2:
			if (r.LocalIP.Equal(net.IPv4(127, 0, 0, 1)) || r.LocalIP.Equal(net.IPv4zero)) && !sockSeen[r.LocalPort] && len(sockSeen) < 10 {
				sockSeen[r.LocalPort] = true
				addr := fmt.Sprintf("127.0.0.1:%d", r.LocalPort)
				if tg.IsSocks5(addr) {
					s.Socks = append(s.Socks, addr)
				}
			}
		}
	}
	for ip := range ipset {
		s.ServerIPs = append(s.ServerIPs, ip)
	}
	sort.Strings(s.ServerIPs)
	sort.Strings(s.Socks)
	return s
}

// firstProxy достаёт адрес из ProxyServer ("127.0.0.1:10809" или "http=...;https=...")
func firstProxy(v string) string {
	for _, part := range strings.Split(v, ";") {
		if i := strings.Index(part, "="); i >= 0 {
			part = part[i+1:]
		}
		if part = strings.TrimSpace(part); part != "" {
			return part
		}
	}
	return ""
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

// ---------- диагностика ----------

func printVPNDetails() {
	title("Подробно: VPN и сеть")
	s := detectVPN()
	if len(s.Procs) > 0 {
		say("  VPN-клиенты: %s (процессов: %d)", strings.Join(s.Procs, ", "), len(s.procPIDs))
	} else {
		say("  VPN-клиенты: не найдены")
	}
	say("  Системный прокси: %s", firstNonEmpty(s.SysProxy, "выключен"))
	bi := bestInterface("1.1.1.1")
	say("  Адаптеры (* - через него идёт интернет):")
	for _, a := range listAdapters() {
		kind := "обычный"
		switch {
		case isPPPoE(a):
			kind = "PPPoE провайдера"
		case isVPNAdapter(a):
			kind = col(cYellow, "VPN")
		case containsAny(a.Name+" "+a.Desc, notVPNAdapterWords):
			kind = "виртуальный (не VPN)"
		case !a.Gateway:
			kind = "без шлюза"
		}
		star := " "
		if a.Index == bi {
			star = col(cGreen, "*")
		}
		say("   %s #%-3d %-28s %-22s %s  [%s]", star, a.Index, firstNonEmpty(a.Name, "?"), strings.Join(a.IPs, ","), kind, a.Desc)
	}
	if bi != 0 {
		found := false
		for _, a := range listAdapters() {
			found = found || a.Index == bi
		}
		if !found {
			say("   %s #%-3d (туннель без IPv4-адаптера)", col(cGreen, "*"), bi)
		}
	}
	say("  Итог: VPN %s; туннель: %s; физический адаптер: %s (#%d)",
		map[bool]string{true: col(cYellow, "есть"), false: "нет"}[s.Active()],
		firstNonEmpty(strings.Join(s.TunNames, ", "), "нет"), firstNonEmpty(s.PhysName, "?"), s.PhysIdx)
	if s.Active() {
		say("  Режим VPN: %s", s.Mode())
	}
	say("  Серверы VPN: %s", firstNonEmpty(strings.Join(s.ServerIPs, ", "), "-"))
	say("  SOCKS5 VPN: %s", firstNonEmpty(strings.Join(s.Socks, ", "), "-"))
}

// ---------- выключение VPN (режим 1) ----------

var procInternetSetOption = syscall.NewLazyDLL("wininet.dll").NewProc("InternetSetOptionW")

// disableLocalSystemProxy выключает системный прокси, если он указывает на 127.0.0.1
// (иначе после закрытия VPN-клиента интернет в браузере пропадёт)
func disableLocalSystemProxy(sp string) bool {
	host, _, err := net.SplitHostPort(strings.TrimPrefix(firstProxy(sp), "http://"))
	if err != nil || (host != "127.0.0.1" && !strings.EqualFold(host, "localhost")) {
		return false
	}
	c := exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
	c.SysProcAttr = hiddenProcAttr()
	if c.Run() != nil {
		return false
	}
	procInternetSetOption.Call(0, 39, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	procInternetSetOption.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
	return true
}

// stopVPN закрывает процессы VPN-клиента и убирает его системный прокси.
func stopVPN(s VPNState) {
	n := 0
	for pidS := range s.procPIDs {
		var pid uint32
		fmt.Sscan(pidS, &pid)
		if pid <= 4 || pid == uint32(os.Getpid()) {
			continue
		}
		h, err := syscall.OpenProcess(0x0001, false, pid) // PROCESS_TERMINATE
		if err != nil {
			continue
		}
		if syscall.TerminateProcess(h, 0) == nil {
			n++
		}
		syscall.CloseHandle(h)
	}
	if n > 0 {
		good("Закрыто процессов VPN: %d", n)
	}
	if disableLocalSystemProxy(s.SysProxy) {
		good("Системный прокси VPN (%s) выключен", s.SysProxy)
	}
}
