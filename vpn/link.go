// Package vpn - встроенный VPN на ядре Xray (запускается отдельным процессом): разбор ссылок
// vless/vmess/trojan/ss/hysteria2/wireguard и подписок, сборка настроек Xray (на каждый сервер -
// свой локальный SOCKS5), проверка серверов, бесплатный Cloudflare WARP.
package vpn

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Server - один сервер VPN.
type Server struct {
	ID     string         `json:"id"`     // по ссылке без названия
	Name   string         `json:"name"`   // из ссылки (#...)
	Proto  string         `json:"proto"`  // vless, vmess, trojan, ss, hysteria2, wireguard
	Host   string         `json:"host"`   // адрес сервера
	Port   int            `json:"port"`   //
	Link   string         `json:"link"`   // исходная ссылка
	Source string         `json:"source"` // own | sub | free | warp
	Out    map[string]any `json:"-"`      // outbound Xray (без tag)
}

// Label - коротко для журнала и списка
func (s *Server) Label() string {
	n := strings.TrimSpace(s.Name)
	if n == "" {
		n = s.Host
	}
	if len([]rune(n)) > 48 {
		n = string([]rune(n)[:48]) + "…"
	}
	return n
}

func linkID(link string) string {
	if i := strings.IndexByte(link, '#'); i >= 0 {
		link = link[:i]
	}
	h := sha1.Sum([]byte(strings.TrimSpace(link)))
	return hex.EncodeToString(h[:5])
}

// Parse разбирает одну ссылку.
func Parse(link string) (*Server, error) {
	link = strings.TrimSpace(link)
	i := strings.Index(link, "://")
	if i <= 0 {
		return nil, errors.New("не ссылка")
	}
	var s *Server
	var err error
	switch strings.ToLower(link[:i]) {
	case "vless":
		s, err = parseVLESS(link)
	case "vmess":
		s, err = parseVMess(link)
	case "trojan":
		s, err = parseTrojan(link)
	case "ss":
		s, err = parseSS(link)
	case "hysteria2", "hy2":
		s, err = parseHy2(link)
	case "wireguard", "wg":
		s, err = parseWG(link)
	default:
		return nil, fmt.Errorf("протокол %s не поддерживается", link[:i])
	}
	if err != nil {
		return nil, err
	}
	if s.Host == "" || s.Port <= 0 || s.Port > 65535 {
		return nil, errors.New("нет адреса или порта")
	}
	s.Link = link
	s.ID = linkID(link)
	return s, nil
}

// ParseList разбирает подписку или любой текст со ссылками (по одной в строке; base64 целиком
// тоже понимает). Повторы убираются, ошибочные строки пропускаются.
func ParseList(text string) []*Server {
	text = strings.TrimSpace(text)
	if !strings.Contains(text, "://") {
		if b, err := decodeB64(text); err == nil && strings.Contains(string(b), "://") {
			text = string(b)
		}
	}
	seen := map[string]bool{}
	var out []*Server
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' || r == ' ' || r == '\t' }) {
		if !strings.Contains(line, "://") || strings.HasPrefix(line, "#") {
			continue
		}
		s, err := Parse(line)
		if err != nil || seen[s.ID] {
			continue
		}
		seen[s.ID] = true
		out = append(out, s)
	}
	return out
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("не base64")
}

// hostPort - адрес из URL (IPv6 в скобках поддерживается)
func hostPort(u *url.URL) (string, int, error) {
	h := u.Hostname()
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		return "", 0, errors.New("плохой порт")
	}
	return h, p, nil
}

func fragName(u *url.URL) string {
	n, err := url.PathUnescape(u.Fragment)
	if err != nil {
		return u.Fragment
	}
	return n
}

// параметры ссылки: q.Get, но без учёта регистра имени
type params url.Values

func (p params) get(names ...string) string {
	for _, n := range names {
		for k, v := range p {
			if strings.EqualFold(k, n) && len(v) > 0 {
				return strings.TrimSpace(v[0])
			}
		}
	}
	return ""
}

func (p params) on(names ...string) bool {
	v := strings.ToLower(p.get(names...))
	return v == "1" || v == "true" || v == "yes"
}

// Отпечатки TLS, которые знает Xray (иначе он не запустится вовсе)
var fingerprints = map[string]bool{"chrome": true, "firefox": true, "safari": true, "ios": true, "android": true, "edge": true,
	"360": true, "qq": true, "random": true, "randomized": true, "randomizednoalpn": true}

func fp(v string) string {
	v = strings.ToLower(v)
	if fingerprints[v] {
		return v
	}
	return "chrome"
}

func splitList(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// stream - streamSettings по стандартным параметрам ссылок (как в v2rayN / Xray share link)
func stream(p params, network, security, defSNI string) (map[string]any, error) {
	ss := map[string]any{}
	network = strings.ToLower(network)
	switch network {
	case "", "tcp", "raw":
		network = "raw"
		if strings.EqualFold(p.get("headerType"), "http") {
			req := map[string]any{"path": []string{def(p.get("path"), "/")}}
			if h := p.get("host"); h != "" {
				req["headers"] = map[string]any{"Host": splitList(h)}
			}
			ss["rawSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		}
	case "ws", "websocket":
		network = "ws"
		ss["wsSettings"] = map[string]any{"path": def(p.get("path"), "/"), "host": p.get("host")}
	case "grpc", "gun":
		network = "grpc"
		g := map[string]any{"serviceName": p.get("serviceName", "path"), "multiMode": strings.EqualFold(p.get("mode"), "multi")}
		if a := p.get("authority"); a != "" {
			g["authority"] = a
		}
		ss["grpcSettings"] = g
	case "xhttp", "splithttp":
		network = "xhttp"
		x := map[string]any{"path": def(p.get("path"), "/"), "host": p.get("host"), "mode": def(p.get("mode"), "auto")}
		if e := p.get("extra"); e != "" {
			var m map[string]any
			if err := json.Unmarshal([]byte(e), &m); err == nil {
				x["extra"] = m
			}
		}
		ss["xhttpSettings"] = x
	case "httpupgrade":
		ss["httpupgradeSettings"] = map[string]any{"path": def(p.get("path"), "/"), "host": p.get("host")}
	case "kcp", "mkcp":
		network = "kcp"
	default:
		return nil, fmt.Errorf("транспорт %s не поддерживается", network)
	}
	ss["network"] = network
	sni := def(p.get("sni", "peer", "serverName"), def(p.get("host"), defSNI))
	if strings.Contains(sni, ",") {
		sni = splitList(sni)[0]
	}
	switch strings.ToLower(security) {
	case "", "none":
		ss["security"] = "none"
	case "tls", "xtls":
		t := map[string]any{"serverName": sni, "fingerprint": fp(p.get("fp", "fingerprint"))}
		if a := splitList(p.get("alpn")); len(a) > 0 {
			t["alpn"] = a
		}
		if pcs := p.get("pcs", "pinnedPeerCertSha256", "pinSHA256"); pcs != "" {
			t["pinnedPeerCertSha256"] = strings.ReplaceAll(pcs, ":", "")
		}
		if v := p.get("vcn", "verifyPeerCertByName"); v != "" {
			t["verifyPeerCertByName"] = v
		}
		if e := p.get("ech"); e != "" {
			t["echConfigList"] = e
		}
		ss["security"] = "tls"
		ss["tlsSettings"] = t
	case "reality":
		pbk := p.get("pbk", "publicKey", "password")
		if pbk == "" {
			return nil, errors.New("REALITY без ключа pbk")
		}
		r := map[string]any{"serverName": sni, "fingerprint": fp(p.get("fp", "fingerprint")), "publicKey": pbk,
			"shortId": p.get("sid", "shortId"), "spiderX": p.get("spx", "spiderX")}
		if v := p.get("pqv", "mldsa65Verify"); v != "" {
			r["mldsa65Verify"] = v
		}
		ss["security"] = "reality"
		ss["realitySettings"] = r
	default:
		return nil, fmt.Errorf("защита %s не поддерживается", security)
	}
	return ss, nil
}

func def(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func parseVLESS(link string) (*Server, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	h, port, err := hostPort(u)
	if err != nil {
		return nil, err
	}
	id := u.User.Username()
	if id == "" {
		return nil, errors.New("нет id")
	}
	p := params(u.Query())
	st, err := stream(p, p.get("type", "net"), p.get("security"), h)
	if err != nil {
		return nil, err
	}
	set := map[string]any{"address": h, "port": port, "id": id, "encryption": def(p.get("encryption"), "none")}
	if f := p.get("flow"); f != "" {
		set["flow"] = f
	}
	return &Server{Name: fragName(u), Proto: "vless", Host: h, Port: port,
		Out: map[string]any{"protocol": "vless", "settings": set, "streamSettings": st}}, nil
}

func parseTrojan(link string) (*Server, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	h, port, err := hostPort(u)
	if err != nil {
		return nil, err
	}
	pw := u.User.Username()
	if pw == "" {
		return nil, errors.New("нет пароля")
	}
	p := params(u.Query())
	st, err := stream(p, p.get("type", "net"), def(p.get("security"), "tls"), h)
	if err != nil {
		return nil, err
	}
	set := map[string]any{"address": h, "port": port, "password": pw}
	return &Server{Name: fragName(u), Proto: "trojan", Host: h, Port: port,
		Out: map[string]any{"protocol": "trojan", "settings": set, "streamSettings": st}}, nil
}

func parseVMess(link string) (*Server, error) {
	raw := strings.TrimPrefix(strings.TrimSpace(link[len("vmess://"):]), "/")
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	b, err := decodeB64(raw)
	if err != nil {
		return nil, errors.New("vmess: не base64")
	}
	var j map[string]any
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, errors.New("vmess: не JSON")
	}
	str := func(k string) string {
		switch v := j[k].(type) {
		case string:
			return strings.TrimSpace(v)
		case float64:
			return strconv.Itoa(int(v))
		}
		return ""
	}
	h := str("add")
	port, _ := strconv.Atoi(str("port"))
	id := str("id")
	if id == "" {
		return nil, errors.New("нет id")
	}
	p := params(url.Values{"path": {str("path")}, "host": {str("host")}, "sni": {str("sni")}, "alpn": {str("alpn")},
		"fp": {str("fp")}, "headerType": {str("type")}, "serviceName": {str("path")}, "mode": {str("mode")}})
	sec := str("tls")
	st, err := stream(p, str("net"), sec, h)
	if err != nil {
		return nil, err
	}
	set := map[string]any{"address": h, "port": port, "id": id, "security": def(str("scy"), "auto")}
	return &Server{Name: str("ps"), Proto: "vmess", Host: h, Port: port,
		Out: map[string]any{"protocol": "vmess", "settings": set, "streamSettings": st}}, nil
}

// Шифры Shadowsocks, которые есть в Xray
var ssCiphers = map[string]bool{"aes-128-gcm": true, "aes-256-gcm": true, "chacha20-poly1305": true, "chacha20-ietf-poly1305": true,
	"xchacha20-poly1305": true, "xchacha20-ietf-poly1305": true, "2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
	"2022-blake3-chacha20-poly1305": true, "none": true, "plain": true}

func parseSS(link string) (*Server, error) {
	rest := link[len("ss://"):]
	name := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	query := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	var userinfo, hp string
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		userinfo, hp = rest[:i], rest[i+1:]
		if u, err := url.PathUnescape(userinfo); err == nil {
			userinfo = u
		}
		if !strings.Contains(userinfo, ":") {
			b, err := decodeB64(userinfo)
			if err != nil {
				return nil, errors.New("ss: плохой ключ")
			}
			userinfo = string(b)
		}
	} else {
		b, err := decodeB64(rest)
		if err != nil {
			return nil, errors.New("ss: не base64")
		}
		s := string(b)
		i := strings.LastIndexByte(s, '@')
		if i < 0 {
			return nil, errors.New("ss: нет адреса")
		}
		userinfo, hp = s[:i], s[i+1:]
	}
	method, pw, ok := strings.Cut(userinfo, ":")
	if !ok {
		return nil, errors.New("ss: нет пароля")
	}
	method = strings.ToLower(method)
	if !ssCiphers[method] {
		return nil, fmt.Errorf("ss: шифр %s не поддерживается", method)
	}
	if q, _ := url.ParseQuery(query); q.Get("plugin") != "" {
		return nil, errors.New("ss: плагины не поддерживаются")
	}
	h, ps, err := net.SplitHostPort(hp)
	if err != nil {
		return nil, errors.New("ss: плохой адрес")
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return nil, errors.New("ss: плохой порт")
	}
	set := map[string]any{"address": h, "port": port, "method": method, "password": pw}
	return &Server{Name: name, Proto: "ss", Host: h, Port: port,
		Out: map[string]any{"protocol": "shadowsocks", "settings": set}}, nil
}

func parseHy2(link string) (*Server, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	h := u.Hostname()
	ps := u.Port()
	if i := strings.IndexAny(ps, ",-"); i >= 0 { // прыжки по портам: берём первый
		ps = ps[:i]
	}
	port, err := strconv.Atoi(def(ps, "443"))
	if err != nil {
		return nil, errors.New("плохой порт")
	}
	auth := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		auth += ":" + pw
	}
	p := params(u.Query())
	t := map[string]any{"serverName": def(p.get("sni", "peer"), h), "alpn": []string{"h3"}}
	if pin := p.get("pinSHA256", "pcs"); pin != "" {
		t["pinnedPeerCertSha256"] = strings.ReplaceAll(pin, ":", "")
	}
	st := map[string]any{"network": "hysteria", "hysteriaSettings": map[string]any{"version": 2, "auth": auth},
		"security": "tls", "tlsSettings": t}
	if o := p.get("obfs"); o != "" {
		if !strings.EqualFold(o, "salamander") {
			return nil, fmt.Errorf("hysteria2: обфускация %s не поддерживается", o)
		}
		st["finalmask"] = map[string]any{"udp": []any{map[string]any{"type": "salamander",
			"settings": map[string]any{"password": p.get("obfs-password", "obfsPassword")}}}}
	}
	return &Server{Name: fragName(u), Proto: "hysteria2", Host: h, Port: port,
		Out: map[string]any{"protocol": "hysteria", "settings": map[string]any{"version": 2, "address": h, "port": port}, "streamSettings": st}}, nil
}

func parseWG(link string) (*Server, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	h, port, err := hostPort(u)
	if err != nil {
		return nil, err
	}
	key := u.User.Username()
	if k, err := url.PathUnescape(key); err == nil {
		key = k
	}
	p := params(u.Query())
	pub := p.get("publickey", "publicKey", "peer_public_key")
	if key == "" || pub == "" {
		return nil, errors.New("wireguard: нет ключей")
	}
	addr := splitList(def(p.get("address", "ip"), "172.16.0.2/32"))
	for i, a := range addr {
		if !strings.Contains(a, "/") {
			if strings.Contains(a, ":") {
				addr[i] = a + "/128"
			} else {
				addr[i] = a + "/32"
			}
		}
	}
	peer := map[string]any{"publicKey": pub, "endpoint": net.JoinHostPort(h, strconv.Itoa(port)), "keepAlive": 25}
	if psk := p.get("presharedkey", "preSharedKey"); psk != "" {
		peer["preSharedKey"] = psk
	}
	set := map[string]any{"secretKey": key, "address": addr, "peers": []any{peer}, "mtu": 1280, "noKernelTun": true}
	if m, err := strconv.Atoi(p.get("mtu")); err == nil && m >= 1000 && m <= 1500 {
		set["mtu"] = m
	}
	if r := p.get("reserved"); r != "" {
		var rb []int
		for _, x := range splitList(r) {
			if n, err := strconv.Atoi(x); err == nil && n >= 0 && n < 256 {
				rb = append(rb, n)
			}
		}
		if len(rb) == 3 {
			set["reserved"] = rb
		}
	}
	out := map[string]any{"protocol": "wireguard", "settings": set}
	if p.on("noise") {
		// мусорные UDP-пакеты перед рукопожатием: DPI не узнаёт WireGuard (так работает WARP в РФ)
		out["streamSettings"] = map[string]any{"finalmask": map[string]any{"udp": []any{map[string]any{"type": "noise",
			"settings": map[string]any{"noise": []any{
				map[string]any{"type": "rand", "rand": "50-120", "delay": "5-15"},
				map[string]any{"type": "rand", "rand": "50-120", "delay": "5-15"},
				map[string]any{"type": "rand", "rand": "50-120", "delay": "5-15"},
			}}}}}}
	}
	return &Server{Name: fragName(u), Proto: "wireguard", Host: h, Port: port, Out: out}, nil
}
