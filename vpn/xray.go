package vpn

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Slot - сервер на своём локальном порту SOCKS5 (127.0.0.1:Port)
type Slot struct {
	Server *Server
	Port   int
}

// Config собирает настройки Xray: на каждый сервер - свой вход SOCKS5 (TCP и UDP) и выход.
// Адреса серверов Xray узнаёт сам через DoH (на Android у программ Linux нет системного DNS),
// и только IPv4 - в сетях без IPv6 иначе соединения висят.
func Config(slots []Slot, logLevel string) ([]byte, error) {
	if len(slots) == 0 {
		return nil, errors.New("нет серверов")
	}
	if logLevel == "" {
		logLevel = "warning"
	}
	var ins, outs, rules []any
	for i, sl := range slots {
		if sl.Server == nil || sl.Server.Out == nil {
			return nil, fmt.Errorf("сервер %d пустой", i)
		}
		in := fmt.Sprintf("in%d", i)
		out := fmt.Sprintf("out%d", i)
		ins = append(ins, map[string]any{"tag": in, "listen": "127.0.0.1", "port": sl.Port, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"}})
		o := cloneMap(sl.Server.Out)
		o["tag"] = out
		st, _ := o["streamSettings"].(map[string]any)
		if st == nil {
			st = map[string]any{}
		}
		so, _ := st["sockopt"].(map[string]any)
		if so == nil {
			so = map[string]any{}
		}
		if sl.Server.Proto != "wireguard" {
			so["domainStrategy"] = "UseIPv4"
		}
		st["sockopt"] = so
		o["streamSettings"] = st
		outs = append(outs, o)
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{in}, "outboundTag": out})
	}
	outs = append(outs, map[string]any{"tag": "direct", "protocol": "freedom"})
	cfg := map[string]any{
		"log": map[string]any{"loglevel": logLevel},
		"dns": map[string]any{
			"servers":       []any{"https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query", "77.88.8.8"},
			"queryStrategy": "UseIPv4",
		},
		"inbounds":  ins,
		"outbounds": outs,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{"handshake": 6, "connIdle": 300,
			"uplinkOnly": 2, "downlinkOnly": 5}}},
	}
	return json.MarshalIndent(cfg, "", " ")
}

func cloneMap(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	json.Unmarshal(b, &out)
	return out
}

// FreePorts - n свободных портов TCP на 127.0.0.1 (подряд не обязательно)
func FreePorts(n int) ([]int, error) {
	var lns []net.Listener
	defer func() {
		for _, l := range lns {
			l.Close()
		}
	}()
	var ports []int
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		lns = append(lns, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

// Proc - запущенный Xray
type Proc struct {
	cmd    *exec.Cmd
	cfg    string
	done   chan struct{}
	mu     sync.Mutex
	tail   []string
	Exited error
}

// Start запускает Xray с настройками и ждёт, пока откроются все порты SOCKS (до 8 с).
// hide - настройка процесса для Windows (скрыть окно), nil на Android.
func Start(xray string, cfg []byte, ports []int, setup func(*exec.Cmd)) (*Proc, error) {
	dir, err := os.MkdirTemp("", "xray")
	if err != nil {
		return nil, err
	}
	f := filepath.Join(dir, "config.json")
	if err := os.WriteFile(f, cfg, 0600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	cmd := exec.Command(xray, "run", "-c", f)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+dir, "XRAY_LOCATION_CONFIG="+dir)
	if setup != nil {
		setup(cmd)
	}
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("Xray не запустился: %v", err)
	}
	p := &Proc{cmd: cmd, cfg: dir, done: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			p.mu.Lock()
			p.tail = append(p.tail, sc.Text())
			if len(p.tail) > 30 {
				p.tail = p.tail[len(p.tail)-30:]
			}
			p.mu.Unlock()
		}
	}()
	go func() {
		p.Exited = cmd.Wait()
		os.RemoveAll(dir)
		close(p.done)
	}()
	deadline := time.Now().Add(8 * time.Second)
	for _, port := range ports {
		for {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
			if err == nil {
				c.Close()
				break
			}
			select {
			case <-p.done:
				return nil, fmt.Errorf("Xray завершился: %s", p.Tail())
			default:
			}
			if time.Now().After(deadline) {
				p.Stop()
				return nil, fmt.Errorf("Xray не открыл порт %d: %s", port, p.Tail())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return p, nil
}

// Tail - последние строки вывода Xray
func (p *Proc) Tail() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.tail
	if len(t) > 6 {
		t = t[len(t)-6:]
	}
	return strings.Join(t, " | ")
}

// Alive - процесс ещё работает
func (p *Proc) Alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// Done - закрывается, когда процесс завершился
func (p *Proc) Done() <-chan struct{} { return p.done }

// Stop останавливает Xray и ждёт завершения (до 3 с)
func (p *Proc) Stop() {
	if p == nil || p.cmd.Process == nil {
		return
	}
	p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
	}
}

// Supervisor держит Xray запущенным: если процесс упал - перезапускает (не чаще раза в 3 с).
type Supervisor struct {
	Xray  string
	Setup func(*exec.Cmd)
	Log   func(format string, a ...any)

	mu     sync.Mutex
	proc   *Proc
	slots  []Slot
	cancel context.CancelFunc
}

func (s *Supervisor) logf(f string, a ...any) {
	if s.Log != nil {
		s.Log(f, a...)
	}
}

// Run запускает (или перезапускает с новыми серверами) Xray. Пустой список - остановить.
func (s *Supervisor) Run(slots []Slot) error {
	s.Stop()
	if len(slots) == 0 {
		return nil
	}
	cfg, err := Config(slots, "")
	if err != nil {
		return err
	}
	ports := make([]int, len(slots))
	for i, sl := range slots {
		ports[i] = sl.Port
	}
	p, err := Start(s.Xray, cfg, ports, s.Setup)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.proc, s.slots, s.cancel = p, slots, cancel
	s.mu.Unlock()
	go s.watch(ctx, cfg, ports)
	return nil
}

func (s *Supervisor) watch(ctx context.Context, cfg []byte, ports []int) {
	for {
		s.mu.Lock()
		p := s.proc
		s.mu.Unlock()
		if p == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-p.Done():
		}
		s.logf("VPN: Xray завершился (%v: %s) - перезапускаю", p.Exited, p.Tail())
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			np, err := Start(s.Xray, cfg, ports, s.Setup)
			if err == nil {
				s.mu.Lock()
				if ctx.Err() != nil {
					s.mu.Unlock()
					np.Stop()
					return
				}
				s.proc = np
				s.mu.Unlock()
				break
			}
			s.logf("VPN: Xray не перезапустился: %v", err)
		}
	}
}

// Stop останавливает Xray
func (s *Supervisor) Stop() {
	s.mu.Lock()
	p, c := s.proc, s.cancel
	s.proc, s.cancel, s.slots = nil, nil, nil
	s.mu.Unlock()
	if c != nil {
		c()
	}
	p.Stop()
}

// Alive - Xray работает
func (s *Supervisor) Alive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.proc != nil && s.proc.Alive()
}

// readAll с ограничением (для ответов серверов)
func readLimited(r io.Reader, n int64) ([]byte, error) { return io.ReadAll(io.LimitReader(r, n)) }
