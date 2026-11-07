package vpn

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func outJSON(t *testing.T, s *Server) map[string]any {
	b, err := json.Marshal(s.Out)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func dig(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func TestVLESSReality(t *testing.T) {
	s, err := Parse("vless://f8d52ece-fad4-478d-875d-df6eed3befa7@fr.example.cfd:443?flow=xtls-rprx-vision&fp=safari&pbk=isYQuhKDrgc7IQ7G0LHywFnt57wffrkZ-er18DkVsBA&security=reality&sid=e6d589857d1cec5e&sni=fr.example.cfd&type=tcp#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam")
	if err != nil {
		t.Fatal(err)
	}
	m := outJSON(t, s)
	if s.Proto != "vless" || s.Host != "fr.example.cfd" || s.Port != 443 || s.Name != "🇳🇱 Amsterdam" {
		t.Fatalf("%+v", s)
	}
	if dig(m, "settings", "flow") != "xtls-rprx-vision" || dig(m, "settings", "encryption") != "none" || dig(m, "settings", "id") != "f8d52ece-fad4-478d-875d-df6eed3befa7" {
		t.Fatal(m["settings"])
	}
	if dig(m, "streamSettings", "network") != "raw" || dig(m, "streamSettings", "security") != "reality" ||
		dig(m, "streamSettings", "realitySettings", "publicKey") != "isYQuhKDrgc7IQ7G0LHywFnt57wffrkZ-er18DkVsBA" ||
		dig(m, "streamSettings", "realitySettings", "shortId") != "e6d589857d1cec5e" ||
		dig(m, "streamSettings", "realitySettings", "fingerprint") != "safari" ||
		dig(m, "streamSettings", "realitySettings", "serverName") != "fr.example.cfd" {
		t.Fatal(m["streamSettings"])
	}
}

func TestVLESSWSTLSAndXHTTP(t *testing.T) {
	s, err := Parse("vless://id1@104.18.0.1:2053?security=tls&sni=a.example.org&type=ws&host=a.example.org&path=%2Fws%3Fed%3D2048&fp=unsafe&alpn=h2%2Chttp%2F1.1#x")
	if err != nil {
		t.Fatal(err)
	}
	m := outJSON(t, s)
	if dig(m, "streamSettings", "network") != "ws" || dig(m, "streamSettings", "wsSettings", "path") != "/ws?ed=2048" ||
		dig(m, "streamSettings", "wsSettings", "host") != "a.example.org" || dig(m, "streamSettings", "tlsSettings", "fingerprint") != "chrome" {
		t.Fatal(m["streamSettings"])
	}
	if a, _ := dig(m, "streamSettings", "tlsSettings", "alpn").([]any); len(a) != 2 {
		t.Fatal("alpn", a)
	}
	s, err = Parse(`vless://id2@188.114.98.0:443?encryption=none&security=tls&type=xhttp&host=nl.example.ir&path=%2F&mode=auto&sni=nl.example.ir&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#y`)
	if err != nil {
		t.Fatal(err)
	}
	m = outJSON(t, s)
	if dig(m, "streamSettings", "network") != "xhttp" || dig(m, "streamSettings", "xhttpSettings", "mode") != "auto" ||
		dig(m, "streamSettings", "xhttpSettings", "extra", "xPaddingBytes") != "100-1000" {
		t.Fatal(m["streamSettings"])
	}
	s, err = Parse("vless://id3@93.190.9.194:3090?encryption=none&security=none&type=grpc&serviceName=vless&mode=multi#z")
	if err != nil {
		t.Fatal(err)
	}
	m = outJSON(t, s)
	if dig(m, "streamSettings", "grpcSettings", "serviceName") != "vless" || dig(m, "streamSettings", "grpcSettings", "multiMode") != true {
		t.Fatal(m["streamSettings"])
	}
}

func TestVMessTrojanSSHy2WG(t *testing.T) {
	vm := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"US","add":"104.17.136.198","port":"443","id":"0cf6d970-3f1d-4aae-a989-92a8f76ae3db","aid":"0","scy":"auto","net":"ws","type":"none","tls":"tls","sni":"v.example.org","path":"/ws","host":"v.example.org","alpn":"","fp":""}`))
	s, err := Parse("vmess://" + vm)
	if err != nil {
		t.Fatal(err)
	}
	m := outJSON(t, s)
	if s.Name != "US" || dig(m, "protocol") != "vmess" || dig(m, "settings", "id") != "0cf6d970-3f1d-4aae-a989-92a8f76ae3db" ||
		dig(m, "streamSettings", "tlsSettings", "serverName") != "v.example.org" || dig(m, "streamSettings", "wsSettings", "path") != "/ws" {
		t.Fatal(m)
	}
	s, err = Parse("trojan://gHQP0D7D15@104.18.0.1:2053?host=m.example.org&path=%2F&security=tls&sni=m.example.org&type=ws#t")
	if err != nil {
		t.Fatal(err)
	}
	m = outJSON(t, s)
	if dig(m, "settings", "password") != "gHQP0D7D15" || dig(m, "streamSettings", "security") != "tls" {
		t.Fatal(m)
	}
	// ss: SIP002 (base64 метод:пароль) и старый формат (всё в base64)
	ui := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pass123"))
	s, err = Parse("ss://" + ui + "@1.2.3.4:8388#ss1")
	if err != nil {
		t.Fatal(err)
	}
	m = outJSON(t, s)
	if dig(m, "protocol") != "shadowsocks" || dig(m, "settings", "method") != "chacha20-ietf-poly1305" || dig(m, "settings", "password") != "pass123" || s.Port != 8388 {
		t.Fatal(m)
	}
	old := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:p@ss:x@5.6.7.8:443"))
	s, err = Parse("ss://" + old + "#ss2")
	if err != nil {
		t.Fatal(err)
	}
	m = outJSON(t, s)
	if s.Host != "5.6.7.8" || dig(m, "settings", "password") != "p@ss:x" {
		t.Fatal(s.Host, m)
	}
	if _, err := Parse("ss://" + ui + "@1.2.3.4:8388?plugin=obfs-local#p"); err == nil {
		t.Fatal("ss с плагином должен отклоняться")
	}
	s, err = Parse("hysteria2://pass@fi.example.net:25482?sni=www.bing.com&pinSHA256=44:97:91&obfs=salamander&obfs-password=xx#h")
	if err != nil {
		t.Fatal(err)
	}
	m = outJSON(t, s)
	if dig(m, "protocol") != "hysteria" || dig(m, "streamSettings", "hysteriaSettings", "auth") != "pass" ||
		dig(m, "streamSettings", "tlsSettings", "pinnedPeerCertSha256") != "449791" || dig(m, "streamSettings", "finalmask") == nil {
		t.Fatal(m)
	}
	s, err = Parse("wireguard://cPrivKey%2Babc%3D@162.159.192.1:2408/?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32%2C2606%3A4700%3A%3A1%2F128&reserved=1%2C2%2C3&mtu=1280&noise=1#WARP")
	if err != nil {
		t.Fatal(err)
	}
	m = outJSON(t, s)
	if dig(m, "settings", "secretKey") != "cPrivKey+abc=" || dig(m, "streamSettings", "finalmask") == nil {
		t.Fatal(m)
	}
	if r, _ := dig(m, "settings", "reserved").([]any); len(r) != 3 {
		t.Fatal("reserved", r)
	}
	peers, _ := dig(m, "settings", "peers").([]any)
	if len(peers) != 1 || peers[0].(map[string]any)["publicKey"] != "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" {
		t.Fatal(peers)
	}
}

func TestWarpLinksParse(t *testing.T) {
	a := &WarpAccount{PrivateKey: "aGVsbG8rL3dvcmxkK2tleWtleWtleWtleWtleWtleWs=", PeerKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", V4: "172.16.0.2", V6: "2606:4700:110::1", Reserved: []int{10, 20, 30}}
	ls := a.Links()
	if len(ls) != 2*len(warpEndpoints) {
		t.Fatal(len(ls))
	}
	for _, l := range ls {
		s, err := Parse(l)
		if err != nil {
			t.Fatal(l, err)
		}
		m := outJSON(t, s)
		if dig(m, "settings", "secretKey") != a.PrivateKey {
			t.Fatal("ключ испорчен", dig(m, "settings", "secretKey"))
		}
	}
}

func TestParseListAndConfig(t *testing.T) {
	sub := "vless://a@1.1.1.1:443?security=none&type=tcp#a\nvless://a@1.1.1.1:443?security=none&type=tcp#a-dup\n# comment\ngarbage\nvmess://bad\n"
	if l := ParseList(sub); len(l) != 1 {
		t.Fatal(len(l))
	}
	if l := ParseList(base64.StdEncoding.EncodeToString([]byte(sub))); len(l) != 1 {
		t.Fatal("base64", len(l))
	}
	l := ParseList(sub)
	cfg, err := Config([]Slot{{Server: l[0], Port: 20801}}, "")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(cfg, &m); err != nil {
		t.Fatal(err)
	}
	ins := m["inbounds"].([]any)
	if ins[0].(map[string]any)["port"].(float64) != 20801 {
		t.Fatal(ins)
	}
	outs := m["outbounds"].([]any)
	if dig(outs[0].(map[string]any), "streamSettings", "sockopt", "domainStrategy") != "UseIPv4" || outs[0].(map[string]any)["tag"] != "out0" {
		t.Fatal(outs[0])
	}
	// исходный сервер не испорчен добавлением tag/sockopt
	if _, ok := l[0].Out["tag"]; ok {
		t.Fatal("tag попал в исходный сервер")
	}
}

// Настоящие бесплатные списки (если лежат рядом): разбирается большинство ссылок
func TestRealLists(t *testing.T) {
	b, err := os.ReadFile(os.Getenv("VPN_SAMPLE"))
	if err != nil {
		t.Skip("нет VPN_SAMPLE")
	}
	total := strings.Count(string(b), "://")
	l := ParseList(string(b))
	t.Logf("ссылок %d, разобрано %d", total, len(l))
	if len(l) < total*7/10 {
		t.Fatalf("разобрано слишком мало: %d из %d", len(l), total)
	}
	protos := map[string]int{}
	for _, s := range l {
		protos[s.Proto]++
		if _, err := json.Marshal(s.Out); err != nil {
			t.Fatal(err)
		}
	}
	t.Log(protos)
}
