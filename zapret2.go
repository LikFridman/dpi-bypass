//go:build windows

package main

// zapret2 (winws2): новое поколение zapret - приёмы на Lua (fake с подменой SNI, multidisorder,
// fakedsplit, hostfakesplit, seqovl...) и автопереключение стратегий для каждого сайта
// (оркестратор circular: если у сайта начинаются повторные отправки - сбой DPI, - winws2 сам
// переходит к следующей стратегии из подобранных, без нового подбора).
//
// Стратегии zapret2 - с номерами z1, z2...; они участвуют в подборе вместе с обычными. Одновременно
// работает один движок: если основная стратегия - из zapret2, вся конфигурация собирается для
// winws2, иначе - для winws (zapret1). Если winws2 не запускается, остаётся winws.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// z2Marker - первый аргумент: запускать winws2.exe (а не winws.exe)
const z2Marker = "@winws2"

// strategiesZ2 - параметры для профиля TLS (ClientHello) winws2
var strategiesZ2 = []Strategy{
	{"z1", "zapret2: fake (SNI google) + multidisorder", []string{"--lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=11:tls_mod=rnd,dupsid,sni=www.google.com", "--lua-desync=multidisorder:pos=1,midsld"}},
	{"z2", "zapret2: fake seq + multidisorder midsld", []string{"--lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000:repeats=6", "--lua-desync=multidisorder:pos=midsld"}},
	{"z3", "zapret2: fakedsplit, autottl", []string{"--lua-desync=fakedsplit:pos=midsld:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5"}},
	{"z4", "zapret2: hostfakesplit (фейковый хост)", []string{"--lua-desync=hostfakesplit:host=www.google.com:tcp_md5:repeats=4"}},
	{"z5", "zapret2: multisplit + seqovl", []string{"--lua-desync=multisplit:pos=1:seqovl=568"}},
	{"z6", "zapret2: fake (случайный SNI) + multisplit", []string{"--lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=6:tls_mod=rnd,rndsni", "--lua-desync=multisplit:pos=1,midsld"}},
	{"z7", "zapret2: fakeddisorder, autottl", []string{"--lua-desync=fakeddisorder:pos=midsld:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5"}},
	{"z8", "zapret2: fake ttl + multidisorder по sniext", []string{"--lua-desync=fake:blob=fake_default_tls:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:repeats=6", "--lua-desync=multidisorder:pos=1,sniext+1"}},
}

// z2Files - файлы winws2 (в той же сборке zapret-win-bundle)
var z2Files = []string{"winws2.exe", "lua/zapret-lib.lua", "lua/zapret-antidpi.lua", "lua/zapret-auto.lua"}

func isZ2(st Strategy) bool { return strings.HasPrefix(st.ID, "z") }

// z2Ready - winws2 и его Lua-библиотеки на месте
var z2Disabled bool // winws2 не запустился на этом компьютере - дальше без него

func z2Ready() bool {
	if z2Disabled {
		return false
	}
	for _, f := range z2Files {
		if !fileExists(zp(f)) {
			return false
		}
	}
	return true
}

// z2Head - общее начало команды winws2: библиотеки Lua и фейковый QUIC
func z2Head() []string {
	return []string{z2Marker,
		"--lua-init=@" + zp("lua/zapret-lib.lua"), "--lua-init=@" + zp("lua/zapret-antidpi.lua"), "--lua-init=@" + zp("lua/zapret-auto.lua"),
		"--blob=quic_google:@" + zp("files/quic_initial_www_google_com.bin"),
		"--blob=discord_udp:@" + fsBin("ACTIVE_DISCORD_UDP.bin")}
}

// z2TLS - профиль TLS: стратегии по порядку; несколько - с автопереключением circular
func z2TLS(list []Strategy) []string {
	var a []string
	if len(list) > 1 {
		// сбой у сайта (повторные отправки ClientHello - DPI глушит) 2 раза за минуту - следующая стратегия
		a = append(a, "--lua-desync=circular:fails=2:time=60")
	}
	a = append(a, "--out-range=-d10", "--payload=tls_client_hello")
	for i, st := range list {
		for _, x := range st.Args {
			if len(list) > 1 {
				x += fmt.Sprintf(":strategy=%d", i+1)
			}
			a = append(a, x)
		}
	}
	return a
}

// testArgsZ2 - проверка одной стратегии zapret2 (только TCP 443)
func testArgsZ2(s Strategy) []string {
	args := append(z2Head(), ifaceArg(curVPN)...)
	args = append(args, "--wf-tcp-out=443", "--filter-tcp=443", "--filter-l7=tls")
	args = append(args, exclArgs()...)
	return append(args, z2TLS([]Strategy{s})...)
}

// z2Alternatives - для сервисов группы: до 3 стратегий zapret2, которые у них работали (лучшая первой)
func z2Alternatives(first Strategy, services []string) []Strategy {
	res := resultsCopy()
	type sc struct {
		st Strategy
		n  int
		kb int
	}
	var cand []sc
	for _, st := range strategiesZ2 {
		if st.ID == first.ID {
			continue
		}
		n, kb := 0, 0
		for _, s := range services {
			if r, ok := res[st.ID][s]; ok && r.OK {
				n++
				kb += r.KBps
			}
		}
		if n > 0 && n == len(services) {
			cand = append(cand, sc{st, n, kb})
		}
	}
	sort.SliceStable(cand, func(i, j int) bool { return cand[i].kb > cand[j].kb })
	out := []Strategy{first}
	for _, c := range cand {
		if len(out) >= 3 {
			break
		}
		out = append(out, c.st)
	}
	return out
}

// z2Pick - стратегия zapret2 для сервисов (если в конфигурации у них стратегия zapret1):
// та, что у них работала, иначе - основная
func z2Pick(services []string, def Strategy) Strategy {
	res := resultsCopy()
	best, bestKB := def, -1
	for _, st := range strategiesZ2 {
		ok, kb := true, 0
		for _, s := range services {
			r, has := res[st.ID][s]
			if !has || !r.OK {
				ok = false
				break
			}
			kb += r.KBps
		}
		if ok && kb > bestKB {
			best, bestKB = st, kb
		}
	}
	return best
}

// useZ2 - собирать ли конфигурацию для winws2: основная стратегия - из zapret2 и winws2 на месте
func useZ2(cfg *Config) bool {
	st, ok := strategyByID(cfg.Best)
	return ok && isZ2(st) && z2Ready()
}

// buildArgsZ2 - итоговая конфигурация winws2 (те же профили, что у winws)
func buildArgsZ2(cfg *Config, svcs []Service, withUDPExtras bool) ([]string, error) {
	listDir := filepath.Join(dataDir, "lists")
	os.MkdirAll(listDir, 0755)
	byName := map[string]Service{}
	for _, s := range svcs {
		byName[s.Name] = s
	}
	best, _ := strategyByID(cfg.Best)
	ex := exclArgs()
	args := append(z2Head(), ifaceArg(curVPN)...)
	args = append(args, "--wf-tcp-out=80,443,"+discordVoicePorts, "--wf-raw-part=@"+zp("windivert.filter/windivert_part.quic_initial_ietf.txt"))
	if withUDPExtras {
		args = append(args,
			"--wf-raw-part=@"+zp("windivert.filter/windivert_part.discord_media.txt"),
			"--wf-raw-part=@"+zp("windivert.filter/windivert_part.stun.txt"))
	}
	// HTTP (порт 80)
	args = append(args, "--filter-tcp=80", "--filter-l7=http")
	args = append(args, ex...)
	args = append(args, "--out-range=-d10", "--payload=http_req",
		"--lua-desync=fake:blob=fake_default_http:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5",
		"--lua-desync=fakedsplit:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5", "--new")

	profile := func(hostArg string, list []Strategy) {
		args = append(args, "--filter-tcp=443", "--filter-l7=tls", hostArg)
		args = append(args, ex...)
		args = append(args, z2TLS(list)...)
		args = append(args, "--new")
	}
	for i, g := range cfg.Groups {
		st, ok := strategyByID(g.Strategy)
		if !ok {
			continue
		}
		var doms []string
		for _, n := range g.Services {
			doms = append(doms, byName[n].Domains...)
		}
		if len(doms) == 0 {
			continue
		}
		if !isZ2(st) {
			st = z2Pick(g.Services, best)
		}
		lf := filepath.Join(listDir, fmt.Sprintf("group%d.txt", i+1))
		if err := os.WriteFile(lf, []byte(strings.Join(doms, "\n")+"\n"), 0644); err != nil {
			return nil, err
		}
		profile("--hostlist="+lf, z2Alternatives(st, g.Services))
	}
	// свои стратегии для отдельных сайтов
	bySt := map[string][]string{}
	for d, id := range cfg.Sites {
		if st, ok := strategyByID(id); ok {
			if !isZ2(st) {
				id = best.ID
			}
			bySt[id] = append(bySt[id], d)
		}
	}
	ids := make([]string, 0, len(bySt))
	for id := range bySt {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		st, _ := strategyByID(id)
		doms := bySt[id]
		sort.Strings(doms)
		lf := filepath.Join(listDir, "site-"+id+".txt")
		if err := os.WriteFile(lf, []byte(strings.Join(doms, "\n")+"\n"), 0644); err != nil {
			return nil, err
		}
		profile("--hostlist="+lf, []Strategy{st})
	}
	// голосовые серверы Discord на портах Cloudflare
	args = append(args, "--filter-tcp="+discordVoicePorts, "--filter-l7=tls", "--hostlist-domains=discord.media")
	args = append(args, ex...)
	args = append(args, z2TLS([]Strategy{best})...)
	args = append(args, "--new")

	own := []string{"workers.dev", "raw.githubusercontent.com"}
	if tgWorkerHost != "" {
		own = append(own, tgWorkerHost)
	}
	profile("--hostlist-domains="+strings.Join(own, ","), []Strategy{best})

	auto := filepath.Join(listDir, "auto-hostlist.txt")
	if !fileExists(auto) {
		os.WriteFile(auto, nil, 0644)
	}
	args = append(args, "--filter-tcp=443", "--filter-l7=tls", "--hostlist-auto="+auto, "--hostlist-auto-fail-threshold=2")
	args = append(args, ex...)
	args = append(args, z2TLS([]Strategy{best})...)
	args = append(args, "--new")

	// QUIC (HTTP/3)
	args = append(args, "--filter-udp=443", "--filter-l7=quic", "--hostlist="+zp("files/list-youtube.txt"))
	args = append(args, ex...)
	args = append(args, "--payload=quic_initial", "--lua-desync=fake:blob=quic_google:repeats=11", "--new",
		"--filter-udp=443", "--filter-l7=quic")
	args = append(args, ex...)
	args = append(args, "--payload=quic_initial", "--lua-desync=fake:blob=fake_default_quic:repeats=11")
	if withUDPExtras {
		// голос Discord и STUN
		args = append(args, "--new", "--filter-l7=discord,stun")
		args = append(args, ex...)
		args = append(args, "--payload=stun,discord_ip_discovery", "--lua-desync=fake:blob=discord_udp:repeats=6")
	}
	return args, nil
}

// z1Pick - стратегия zapret1 для сервисов (когда работает winws, а выбрана стратегия zapret2)
func z1Pick(services []string) Strategy {
	res := resultsCopy()
	best, bestKB := strategies[0], -1
	for _, st := range zapret1Strategies() {
		ok, kb := true, 0
		for _, s := range services {
			r, has := res[st.ID][s]
			if !has || !r.OK {
				ok = false
				break
			}
			kb += r.KBps
		}
		if ok && kb > bestKB {
			best, bestKB = st, kb
		}
	}
	return best
}

// ensureZ2Files - скачать winws2 и библиотеки Lua, если их нет (не обязательно: без них - zapret1)
func ensureZ2Files() {
	var miss []string
	for _, f := range z2Files {
		if !fileExists(zp(f)) {
			miss = append(miss, f)
		}
	}
	if len(miss) == 0 || zapDir != filepath.Join(dataDir, "zapret-winws") {
		return
	}
	cl := &http.Client{Timeout: 60 * time.Second}
	for _, f := range miss {
		var err error
		for _, base := range zapretBases {
			if err = download(cl, base+f, zp(f)); err == nil {
				break
			}
		}
		if err != nil {
			info("zapret2 (winws2) не скачался (%v) - работаю на zapret1", err)
			return
		}
	}
	good("zapret2 (winws2) скачан")
}
