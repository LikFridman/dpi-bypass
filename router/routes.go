package router

// Маршруты сервисов: у каждого сервиса - способы по порядку (основной и запасные): копия byedpi
// со стратегией, VPN (локальный SOCKS Xray), напрямую, а для Telegram ещё WebSocket и публичные
// MTProto-прокси. Маршрутизатор сам переключается на запасной способ, если основной перестал
// отвечать (по настоящим соединениям приложений и по своей проверке раз в 20 с), и возвращается,
// когда основной снова работает.

import (
	"context"
	"dpibypass/check"
	"dpibypass/tg"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Особые способы (кроме адресов SOCKS5)
const (
	UpDirect  = "direct"   // без обхода
	UpTGWS    = "tg-ws"    // Telegram: WebSocket к web.telegram.org через byedpi по умолчанию
	UpTGProxy = "tg-proxy" // Telegram: публичные MTProto-прокси
)

type upState struct {
	fails     int
	firstFail time.Time
	badUntil  time.Time
	ok        bool
	checked   bool
	ping      int
	err       string
	checkedAt time.Time
	used      int64
}

type route struct {
	g    Group
	nets []*net.IPNet
	mu   sync.Mutex
	st   map[string]*upState
	cur  [2]string // последний выбранный способ [сайты, MTProto] (для журнала о переключении)
	used time.Time // последнее соединение приложения
}

func (rt *route) state(up string) *upState {
	s := rt.st[up]
	if s == nil {
		s = &upState{}
		rt.st[up] = s
	}
	return s
}

func isTGOnly(up string) bool { return up == UpTGWS || up == UpTGProxy }

// pick - первый исправный способ; mtproto=false - соединение не MTProto (сайт), особые способы
// Telegram для него не годятся. Если сломано всё - первый по списку.
func (rt *route) pick(mtproto bool) []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	now := time.Now()
	var good, bad []string
	for _, u := range rt.g.Upstreams {
		if !mtproto && isTGOnly(u) {
			continue
		}
		if now.Before(rt.state(u).badUntil) {
			bad = append(bad, u)
		} else {
			good = append(good, u)
		}
	}
	if rt.g.Fastest {
		// проверенные и рабочие - по задержке; затем непроверенные; затем не ответившие при проверке
		rank := func(u string) (int, int) {
			s := rt.state(u)
			switch {
			case s.checked && s.ok:
				return 0, s.ping
			case !s.checked:
				return 1, 0
			}
			return 2, 0
		}
		sort.SliceStable(good, func(a, b int) bool {
			ra, pa := rank(good[a])
			rb, pb := rank(good[b])
			if ra != rb {
				return ra < rb
			}
			return pa < pb
		})
	}
	return append(good, bad...)
}

// report - итог соединения через способ up (по настоящему трафику приложений)
func (r *Router) report(rt *route, up string, ok bool, why string) {
	rt.mu.Lock()
	s := rt.state(up)
	s.used++
	switched := ""
	if ok {
		s.fails = 0
		if !s.badUntil.IsZero() && time.Now().Before(s.badUntil) {
			s.badUntil = time.Time{}
		}
	} else {
		if time.Since(s.firstFail) > time.Minute {
			s.fails, s.firstFail = 0, time.Now()
		}
		s.fails++
		if s.fails >= 3 && time.Now().After(s.badUntil) && len(rt.g.Upstreams) > 1 {
			s.badUntil = time.Now().Add(3 * time.Minute)
			s.err = why
			switched = up
		}
	}
	rt.mu.Unlock()
	if switched != "" {
		r.logf("%s: %s не отвечает (%s) - перевожу на запасной способ", rt.g.Name, r.upName(switched), why)
	}
}

// upName - понятное имя способа для журнала
func (r *Router) upName(up string) string {
	if n, ok := r.cfg.Names[up]; ok && n != "" {
		return n
	}
	switch up {
	case UpDirect:
		return "напрямую"
	case UpTGWS:
		return "WebSocket"
	case UpTGProxy:
		return "MTProto-прокси"
	}
	return up
}

func (r *Router) buildRoutes() {
	for _, g := range r.cfg.Groups {
		if len(g.Upstreams) == 0 && g.Upstream != "" {
			g.Upstreams = []string{g.Upstream}
		}
		if len(g.Upstreams) == 0 {
			continue
		}
		if g.Name == "" {
			g.Name = strings.Join(g.Domains, ",")
		}
		r.routes = append(r.routes, &route{g: g, nets: mustCIDRs(g.CIDRs...), st: map[string]*upState{}})
	}
	for _, l := range r.cfg.TGProxies {
		if u, err := tg.ParseUpstream(l); err == nil {
			r.tgUps = append(r.tgUps, u)
		}
	}
}

// SetTGProxies заменяет список MTProto-прокси; возвращает, сколько разобрано
func (r *Router) SetTGProxies(links []string) int {
	var ups []tg.Upstream
	for _, l := range links {
		if u, err := tg.ParseUpstream(l); err == nil {
			ups = append(ups, u)
		}
	}
	r.tgMu.Lock()
	r.tgUps = ups
	r.tgMu.Unlock()
	return len(ups)
}

// routeFor - маршрут по адресу (для соединений без имени) или по имени сайта
func (r *Router) routeFor(ip net.IP, name string) *route {
	if ip != nil {
		for _, rt := range r.routes {
			if len(rt.nets) > 0 && inNets(ip, rt.nets) {
				return rt
			}
		}
	}
	if name != "" {
		for _, rt := range r.routes {
			if matchDomain(name, rt.g.Domains) {
				return rt
			}
		}
	}
	return nil
}

// dialUp - соединение с target через способ up (SOCKS5 или напрямую)
func (r *Router) dialUp(up, target string) (net.Conn, error) {
	if up == UpDirect {
		return net.DialTimeout("tcp", target, 10*time.Second)
	}
	return tg.SocksDial(up, target)
}

// serveRoute ведёт соединение по маршруту сервиса с переходом на запасной способ, пока клиенту
// ещё ничего не отправлено. tgInit - соединение приложения Telegram (MTProto) к ip.
func (r *Router) serveRoute(rt *route, c net.Conn, target string, ip net.IP, first []byte, mtproto bool) {
	ups := rt.pick(mtproto)
	if len(ups) == 0 {
		r.countGroup(r.cfg.Default)
		r.pipeVia(c, r.cfg.Default, target, first, nil)
		return
	}
	k := 0
	if mtproto {
		k = 1
	}
	rt.mu.Lock()
	rt.used = time.Now()
	rt.mu.Unlock()
	for i, up := range ups {
		last := i == len(ups)-1
		rt.mu.Lock()
		changed := rt.cur[k] != up && rt.cur[k] != ""
		rt.cur[k] = up
		rt.mu.Unlock()
		if changed {
			r.logf("%s: теперь через %s", rt.g.Name, r.upName(up))
		}
		r.countGroup(up)
		switch up {
		case UpTGWS:
			cc := &prefixConn{Conn: c, prefix: first[64:]}
			dial := func(addr string) (net.Conn, error) { return tg.SocksDial(r.cfg.Default, addr) }
			if r.tgpx.BridgeDirect(cc, first[:64], ip, dial) {
				r.St.TGWS.Add(1)
				r.report(rt, up, true, "")
				return
			}
			r.report(rt, up, false, "WebSocket не открылся")
			continue
		case UpTGProxy:
			if r.tgRelay(c, first, ip) {
				r.report(rt, up, true, "")
				return
			}
			r.report(rt, up, false, "прокси не ответили")
			continue
		}
		res := r.pipeViaOpt(c, up, target, first, nil, !last)
		switch {
		case res.retry:
			r.report(rt, up, false, "сервер сбросил соединение")
			continue // приложение ничего не получило - то же начало отправляем следующим способом
		case res.dialErr != nil:
			r.report(rt, up, false, shortReason(res.dialErr))
			if !last {
				continue // клиент ещё ничего не получил - пробуем следующий способ
			}
		case res.got == 0 && res.upFirst && res.d < 20*time.Second:
			r.report(rt, up, false, "сервер не ответил")
		case res.got > 0:
			r.report(rt, up, true, "")
		}
		return
	}
}

func shortReason(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		s = s[i+2:]
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// tgRelay - прямое подключение Telegram через публичные MTProto-прокси (сначала исправные)
func (r *Router) tgRelay(c net.Conn, first []byte, ip net.IP) bool {
	r.tgMu.Lock()
	ups := append([]tg.Upstream{}, r.tgUps...)
	bad := r.tgBadUp
	r.tgMu.Unlock()
	sort.SliceStable(ups, func(a, b int) bool {
		return !time.Now().Before(bad[ups[a].Addr]) && time.Now().Before(bad[ups[b].Addr])
	})
	cc := &prefixConn{Conn: c, prefix: first[64:]}
	for i, u := range ups {
		if i >= 3 {
			break
		}
		if r.tgpx.BridgeDirectRelay(cc, first[:64], ip, u) {
			return true
		}
		r.tgMu.Lock()
		if r.tgBadUp == nil {
			r.tgBadUp = map[string]time.Time{}
		}
		r.tgBadUp[u.Addr] = time.Now().Add(5 * time.Minute)
		r.tgMu.Unlock()
	}
	return false
}

// ---------- своя проверка способов ----------

// checkUp - работает ли способ up у сервиса rt: задержка (мс) или ошибка
func (r *Router) checkUp(rt *route, up string) (int, error) {
	t := 8 * time.Second
	isTG := rt.g.Check == "tg"
	start := time.Now()
	switch {
	case up == UpTGWS:
		d, err := tg.CheckWS(func(addr string) (net.Conn, error) { return tg.SocksDial(r.cfg.Default, addr) }, t)
		return int(d.Milliseconds()), err
	case up == UpTGProxy:
		r.tgMu.Lock()
		ups := append([]tg.Upstream{}, r.tgUps...)
		r.tgMu.Unlock()
		if len(ups) == 0 {
			return 0, fmt.Errorf("нет прокси")
		}
		var last error
		for i, u := range ups {
			if i >= 3 {
				break
			}
			d, err := tg.CheckUpstream(u, t)
			if err == nil {
				return int(d.Milliseconds()), nil
			}
			last = err
		}
		return 0, last
	case isTG:
		d, err := tg.CheckDC(func(addr string) (net.Conn, error) { return r.dialUp(up, addr) }, 2, t)
		return int(d.Milliseconds()), err
	}
	host := rt.g.Check
	if host == "" && len(rt.g.Domains) > 0 {
		host = rt.g.Domains[0]
	}
	if host == "" {
		return 0, fmt.Errorf("нечего проверять")
	}
	c, err := r.dialUp(up, net.JoinHostPort(host, "443"))
	if err != nil {
		return 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(t))
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()
	if err := check.ChromeHandshake(ctx, c, host); err != nil {
		return 0, err
	}
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

// checkRoute проверяет способы сервиса (all - все, иначе текущий и тех, что выше него по списку)
func (r *Router) checkRoute(rt *route, all bool) {
	ups := rt.g.Upstreams
	if !all {
		cur := rt.pick(rt.g.Check == "tg")
		if len(cur) == 0 {
			return
		}
		var sel []string
		for _, u := range ups {
			sel = append(sel, u)
			if u == cur[0] {
				break
			}
		}
		ups = sel
	}
	var wg sync.WaitGroup
	for _, up := range ups {
		wg.Add(1)
		go func(up string) {
			defer wg.Done()
			ms, err := r.checkUp(rt, up)
			rt.mu.Lock()
			s := rt.state(up)
			s.checked, s.checkedAt = true, time.Now()
			wasBad := time.Now().Before(s.badUntil)
			if err != nil {
				s.ok, s.ping, s.err = false, 0, shortReason(err)
				s.fails++
				if s.fails >= 2 && len(rt.g.Upstreams) > 1 && !wasBad {
					s.badUntil = time.Now().Add(3 * time.Minute)
					rt.mu.Unlock()
					r.logf("%s: %s не работает (%s) - перевожу на запасной способ", rt.g.Name, r.upName(up), s.err)
					return
				}
			} else {
				s.ok, s.ping, s.err, s.fails = true, ms, "", 0
				if wasBad {
					s.badUntil = time.Time{}
					rt.mu.Unlock()
					r.logf("%s: %s снова работает (%d ms)", rt.g.Name, r.upName(up), ms)
					return
				}
			}
			rt.mu.Unlock()
		}(up)
	}
	wg.Wait()
	r.afterCheck(rt)
}

// afterCheck: текущий способ не ответил на проверке, а другой отвечает - переводим сразу, не дожидаясь второго сбоя
func (r *Router) afterCheck(rt *route) {
	cur := rt.pick(rt.g.Check == "tg")
	if len(cur) < 2 {
		return
	}
	rt.mu.Lock()
	s := rt.state(cur[0])
	alt := ""
	for _, u := range cur[1:] {
		if st := rt.state(u); st.checked && st.ok && time.Since(st.checkedAt) < time.Minute {
			alt = u
			break
		}
	}
	switched := s.checked && !s.ok && alt != "" && !time.Now().Before(s.badUntil)
	if switched {
		s.badUntil = time.Now().Add(3 * time.Minute)
	}
	why := s.err
	rt.mu.Unlock()
	if switched {
		r.logf("%s: %s не ответил на проверке (%s) - перевожу на %s", rt.g.Name, r.upName(cur[0]), why, r.upName(alt))
	}
}

func (r *Router) checker(ctx context.Context) {
	// сразу после запуска - все способы сервисов «самый быстрый», чтобы основной был выбран по скорости
	for _, rt := range r.routes {
		if rt.g.Fastest && len(rt.g.Upstreams) > 1 {
			go r.checkRoute(rt, true)
		}
	}
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		n++
		for _, rt := range r.routes {
			if rt.g.Check == "" && len(rt.g.Upstreams) < 2 {
				continue
			}
			if len(rt.g.Upstreams) == 1 && rt.g.Upstreams[0] == UpDirect {
				continue
			}
			// сервисом давно не пользовались и он на основном способе - не тратим трафик на проверки
			rt.mu.Lock()
			idle := time.Since(rt.used) > 3*time.Minute
			rt.mu.Unlock()
			act := rt.pick(rt.g.Check == "tg")
			onBackup := len(act) > 0 && act[0] != rt.g.Upstreams[0]
			if idle && !onBackup {
				continue
			}
			// «самый быстрый»: раз в 3 минуты перемеряем все способы, иначе - текущий и те, что выше
			r.checkRoute(rt, rt.g.Fastest && n%6 == 0)
		}
	}
}

// ---------- состояние для приложения ----------

// UpInfo - состояние одного способа
type UpInfo struct {
	Up     string `json:"up"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Ping   int    `json:"ping"`
	Err    string `json:"err,omitempty"`
	Bad    bool   `json:"bad"`
	Active bool   `json:"active"`
	Used   int64  `json:"used"`
	Age    int    `json:"age"` // с последней проверки, с (-1 - не проверялся)
}

// RouteInfo - состояние маршрута сервиса
type RouteInfo struct {
	Name   string   `json:"name"`
	Active string   `json:"active"`
	Ping   int      `json:"ping"`
	OK     bool     `json:"ok"`
	Ups    []UpInfo `json:"ups"`
}

// Routes - состояние всех маршрутов
func (r *Router) Routes() []RouteInfo {
	var out []RouteInfo
	for _, rt := range r.routes {
		act := rt.pick(rt.g.Check == "tg")
		rt.mu.Lock()
		ri := RouteInfo{Name: rt.g.Name}
		if len(act) > 0 {
			ri.Active = act[0]
		}
		for _, u := range rt.g.Upstreams {
			s := rt.state(u)
			age := -1
			if s.checked {
				age = int(time.Since(s.checkedAt).Seconds())
			}
			ui := UpInfo{Up: u, Name: r.upName(u), OK: s.ok, Ping: s.ping, Err: s.err, Bad: time.Now().Before(s.badUntil),
				Active: u == ri.Active, Used: s.used, Age: age}
			if ui.Active {
				ri.Ping, ri.OK = s.ping, s.ok
			}
			ri.Ups = append(ri.Ups, ui)
		}
		rt.mu.Unlock()
		out = append(out, ri)
	}
	return out
}

// CheckNow - проверить все способы сервиса name (пусто - всех сервисов) и вернуть состояние
func (r *Router) CheckNow(name string) []RouteInfo {
	var wg sync.WaitGroup
	for _, rt := range r.routes {
		if name != "" && !strings.EqualFold(rt.g.Name, name) {
			continue
		}
		wg.Add(1)
		go func(rt *route) { defer wg.Done(); r.checkRoute(rt, true) }(rt)
	}
	wg.Wait()
	var out []RouteInfo
	for _, ri := range r.Routes() {
		if name == "" || strings.EqualFold(ri.Name, name) {
			out = append(out, ri)
		}
	}
	return out
}

// serveControl - HTTP для приложения: /state и /check?name=
func (r *Router) serveControl(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	r.ctl = ln
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/state", func(w http.ResponseWriter, q *http.Request) {
		write(w, map[string]any{"routes": r.Routes(), "vpn": r.VPNAlive()})
	})
	// новый список MTProto-прокси для способа tg-proxy (без перезапуска маршрутизатора)
	mux.HandleFunc("/tgproxies", func(w http.ResponseWriter, q *http.Request) {
		if q.Method != http.MethodPost {
			http.Error(w, "POST", http.StatusMethodNotAllowed)
			return
		}
		var links []string
		if err := json.NewDecoder(http.MaxBytesReader(w, q.Body, 1<<20)).Decode(&links); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		write(w, map[string]any{"proxies": r.SetTGProxies(links)})
	})
	mux.HandleFunc("/check", func(w http.ResponseWriter, q *http.Request) {
		write(w, map[string]any{"routes": r.CheckNow(q.URL.Query().Get("name")), "vpn": r.VPNAlive()})
	})
	go (&http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}).Serve(ln)
	return nil
}
