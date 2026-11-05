//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------- привязка к физическому адаптеру (когда включён VPN в режиме TUN) ----------

var (
	bindIfIdx  atomic.Uint32 // 0 - без привязки
	skipSysDNS atomic.Bool   // системный DNS идёт через VPN - не доверяем ему
)

const ipUnicastIf = 31 // IP_UNICAST_IF

func newDialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	idx := bindIfIdx.Load()
	if idx != 0 {
		d.Control = func(network, address string, c syscall.RawConn) error {
			var serr error
			c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIf, int(bits.ReverseBytes32(idx)))
			})
			return serr
		}
	}
	return d
}

type Stage int

const (
	StOK Stage = iota
	StDNS
	StTCP
	StTLS
	StData
	StThrottle
)

type Result struct {
	Stage  Stage
	Reason string
}

func (r Result) OK() bool { return r.Stage == StOK }

// ---------- DNS ----------

type ipInfo struct {
	IP     net.IP
	DNSBad bool // системный DNS подменён или не ответил, IP взят из DoH
}

var (
	ipCacheMu sync.Mutex
	ipCache   = map[string]ipInfo{}
)

func usableIP(ip net.IP) bool {
	ip = ip.To4()
	if ip != nil && ip[0] == 198 && (ip[1] == 18 || ip[1] == 19) {
		return false // 198.18.0.0/15 - fake-ip VPN-клиентов
	}
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() &&
		!ip.IsLinkLocalUnicast() && !ip.Equal(net.IPv4bcast)
}

func systemLookup(host string) []net.IP {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ips, _ := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	return ips
}

var dohServers = []string{
	"https://1.1.1.1/dns-query?name=%s&type=A",
	"https://8.8.8.8/resolve?name=%s&type=A",
	"https://9.9.9.9:5053/dns-query?name=%s&type=A",
}

func dohClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{Proxy: nil, TLSHandshakeTimeout: 4 * time.Second,
			DialContext: newDialer(4 * time.Second).DialContext},
	}
}

func dohLookup(host string) net.IP {
	cl := dohClient()
	for _, tmpl := range dohServers {
		req, _ := http.NewRequest("GET", fmt.Sprintf(tmpl, host), nil)
		req.Header.Set("Accept", "application/dns-json")
		resp, err := cl.Do(req)
		if err != nil {
			continue
		}
		var data struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&data)
		resp.Body.Close()
		if err != nil {
			continue
		}
		for _, a := range data.Answer {
			if a.Type == 1 {
				if ip := net.ParseIP(a.Data); usableIP(ip) {
					return ip
				}
			}
		}
	}
	return nil
}

func resolve(host string) (ipInfo, bool) {
	ipCacheMu.Lock()
	if v, ok := ipCache[host]; ok {
		ipCacheMu.Unlock()
		return v, true
	}
	ipCacheMu.Unlock()

	var res ipInfo
	if skipSysDNS.Load() {
		// VPN перехватывает DNS: берём настоящий адрес через DoH мимо VPN
		res.IP = dohLookup(host)
		if res.IP == nil {
			for _, ip := range systemLookup(host) {
				if usableIP(ip) {
					res.IP = ip
					break
				}
			}
		}
	} else {
		for _, ip := range systemLookup(host) {
			if usableIP(ip) {
				res.IP = ip
				break
			}
		}
		if res.IP == nil {
			if ip := dohLookup(host); ip != nil {
				res = ipInfo{IP: ip, DNSBad: true}
			}
		}
	}
	if res.IP == nil {
		return res, false
	}
	ipCacheMu.Lock()
	ipCache[host] = res
	ipCacheMu.Unlock()
	return res, true
}

// ---------- проверка одного хоста ----------

const (
	bodyLimit = 96 << 10
	dialTO    = 5 * time.Second
	totalTO   = 9 * time.Second
)

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isReset(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "reset") || strings.Contains(s, "forcibly closed") ||
		strings.Contains(s, "aborted") || strings.Contains(s, "eof")
}

func probeHost(host string) Result {
	ii, ok := resolve(host)
	if !ok {
		return Result{StDNS, "не удалось узнать IP (DNS не отвечает)"}
	}
	conn, err := newDialer(dialTO).Dial("tcp4", net.JoinHostPort(ii.IP.String(), "443"))
	if err != nil {
		return Result{StTCP, "нет TCP-соединения: блокировка по IP или сервер недоступен"}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(totalTO))

	tc := tls.Client(conn, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
	if err := tc.Handshake(); err != nil {
		switch {
		case isTimeout(err):
			return Result{StTLS, "DPI: TLS завис (блокировка по SNI)"}
		case isReset(err):
			return Result{StTLS, "DPI: соединение сброшено на TLS"}
		default:
			return Result{StTLS, "ошибка TLS: " + shortErr(err)}
		}
	}
	fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", host)
	n, err := io.Copy(io.Discard, io.LimitReader(tc, bodyLimit))
	switch {
	case err == nil && n > 0, n >= bodyLimit:
		return Result{StOK, ""}
	case n == 0:
		return Result{StData, "DPI: после TLS нет ответа"}
	case isTimeout(err) || isReset(err):
		return Result{StThrottle, fmt.Sprintf("обрыв после %d КБ (ограничение по объёму)", n>>10)}
	default:
		return Result{StOK, ""}
	}
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// ---------- проверка сервиса ----------

type SvcResult struct {
	OK     bool
	Hosts  map[string]Result
	Reason string // главная причина, если не OK
	Stage  Stage  // худшая стадия
	DNSBad bool
}

func probeService(s Service) SvcResult {
	res := SvcResult{OK: true, Hosts: map[string]Result{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range s.Probes {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			r := probeHost(h)
			mu.Lock()
			res.Hosts[h] = r
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	for _, h := range s.Probes {
		r := res.Hosts[h]
		if ii, ok := resolve(h); ok && ii.DNSBad {
			res.DNSBad = true
		}
		if !r.OK() {
			if res.OK || r.Stage < res.Stage { // самая ранняя стадия - самая показательная
				res.Stage, res.Reason = r.Stage, r.Reason
			}
			res.OK = false
		}
	}
	return res
}

func probeAll(svcs []Service) map[string]SvcResult {
	out := map[string]SvcResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, s := range svcs {
		wg.Add(1)
		go func(s Service) {
			defer wg.Done()
			r := probeService(s)
			mu.Lock()
			out[s.Name] = r
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	return out
}
