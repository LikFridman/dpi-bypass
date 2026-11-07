package router

import (
	"context"
	"dpibypass/doh"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// parseUDPHeader разбирает заголовок SOCKS5 UDP: возвращает адрес назначения и данные
func parseUDPHeader(b []byte) (host string, port int, data []byte, err error) {
	if len(b) < 4 || b[2] != 0 {
		return "", 0, nil, errors.New("фрагменты не поддерживаются")
	}
	p := b[4:]
	switch b[3] {
	case 1:
		if len(p) < 6 {
			return "", 0, nil, io.ErrShortBuffer
		}
		host, p = net.IP(p[:4]).String(), p[4:]
	case 4:
		if len(p) < 18 {
			return "", 0, nil, io.ErrShortBuffer
		}
		host, p = net.IP(p[:16]).String(), p[16:]
	case 3:
		if len(p) < 1 || len(p) < 1+int(p[0])+2 {
			return "", 0, nil, io.ErrShortBuffer
		}
		host, p = string(p[1:1+int(p[0])]), p[1+int(p[0]):]
	default:
		return "", 0, nil, errors.New("тип адреса")
	}
	return host, int(binary.BigEndian.Uint16(p)), p[2:], nil
}

func udpHeader(addr *net.UDPAddr) []byte {
	h := []byte{0, 0, 0}
	if v4 := addr.IP.To4(); v4 != nil {
		h = append(append(h, 1), v4...)
	} else {
		h = append(append(h, 4), addr.IP.To16()...)
	}
	return append(h, byte(addr.Port>>8), byte(addr.Port))
}

func (r *Router) handleUDP(c net.Conn) {
	r.St.UDP.Add(1)
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer local.Close()
	lp := local.LocalAddr().(*net.UDPAddr).Port
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(lp >> 8), byte(lp)})
	c.SetDeadline(time.Time{})

	var mu sync.Mutex
	var client *net.UDPAddr
	var direct *net.UDPConn
	var up *upstreamUDP
	closed := make(chan struct{})
	defer func() {
		close(closed)
		mu.Lock()
		if direct != nil {
			direct.Close()
		}
		if up != nil {
			up.close()
		}
		mu.Unlock()
	}()
	reply := func(b []byte) {
		mu.Lock()
		cl := client
		mu.Unlock()
		if cl != nil {
			local.WriteToUDP(b, cl)
		}
	}

	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := local.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			client = from
			mu.Unlock()
			pkt := append([]byte{}, buf[:n]...)
			host, port, data, err := parseUDPHeader(pkt)
			if err != nil {
				continue
			}
			if port == 53 && !r.IPv6() && dnsQType(data) == 28 {
				// AAAA там, где у сети нет IPv6: пустой ответ - приложения сразу идут по IPv4
				r.St.AAAAEmpty.Add(1)
				if ip := net.ParseIP(host); ip != nil {
					reply(append(udpHeader(&net.UDPAddr{IP: ip, Port: 53}), dnsEmpty(data)...))
				}
				continue
			}
			if port == 53 && r.dns != nil {
				// DNS-запрос приложения: отвечаем через зашифрованный DNS (провайдер не подменит)
				r.St.DNS.Add(1)
				go func(host string, data []byte) {
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer cancel()
					resp, err := r.dns.Exchange(ctx, data)
					if err != nil {
						r.St.DNSFail.Add(1)
						if len(data) < 12 {
							return
						}
						resp = dnsServfail(data)
					}
					ip := net.ParseIP(host)
					if ip == nil {
						return
					}
					reply(append(udpHeader(&net.UDPAddr{IP: ip, Port: 53}), resp...))
				}(host, append([]byte{}, data...))
				continue
			}
			if port == 443 && r.cfg.BlockQUIC {
				r.St.QUICDropped.Add(1)
				continue // QUIC: приложение перейдёт на TCP, где работает обход
			}
			if r.udpViaUpstream(port, host) {
				mu.Lock()
				if up == nil {
					u, err := dialUpstreamUDP(r.cfg.UDPUpstream, reply)
					if err != nil {
						r.logf("UDP через byedpi не открылся (%v) - напрямую", err)
						r.cfg.UDPUpstream = ""
					} else {
						up = u
					}
				}
				u := up
				mu.Unlock()
				if u != nil {
					u.send(pkt)
					continue
				}
			}
			mu.Lock()
			if direct == nil {
				d, err := net.ListenUDP("udp", nil)
				if err != nil {
					mu.Unlock()
					continue
				}
				direct = d
				go func(d *net.UDPConn) {
					rb := make([]byte, 64<<10)
					for {
						n, src, err := d.ReadFromUDP(rb)
						if err != nil {
							return
						}
						reply(append(udpHeader(src), rb[:n]...))
					}
				}(d)
			}
			d := direct
			mu.Unlock()
			dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err == nil {
				d.WriteToUDP(data, dst)
			}
		}
	}()
	// ассоциация живёт, пока открыто управляющее TCP-соединение
	io.Copy(io.Discard, c)
}

// upstreamUDP - UDP ASSOCIATE к byedpi (для голоса Discord с фейковыми пакетами)
type upstreamUDP struct {
	ctl  net.Conn
	conn *net.UDPConn
}

func dialUpstreamUDP(up string, reply func([]byte)) (*upstreamUDP, error) {
	ctl, err := net.DialTimeout("tcp", up, 3*time.Second)
	if err != nil {
		return nil, err
	}
	ctl.SetDeadline(time.Now().Add(5 * time.Second))
	ctl.Write([]byte{5, 1, 0})
	g := make([]byte, 2)
	if _, err := io.ReadFull(ctl, g); err != nil || g[1] != 0 {
		ctl.Close()
		return nil, errors.New("SOCKS5 не принял")
	}
	ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	h := make([]byte, 4)
	if _, err := io.ReadFull(ctl, h); err != nil || h[1] != 0 {
		ctl.Close()
		return nil, errors.New("UDP ASSOCIATE отклонён")
	}
	bnd, err := readAddr(ctl, h[3])
	if err != nil {
		ctl.Close()
		return nil, err
	}
	ctl.SetDeadline(time.Time{})
	bh, bp, _ := net.SplitHostPort(bnd)
	if ip := net.ParseIP(bh); ip == nil || ip.IsUnspecified() {
		bh, _, _ = net.SplitHostPort(up)
	}
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bh, bp))
	if err != nil {
		ctl.Close()
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		ctl.Close()
		return nil, err
	}
	u := &upstreamUDP{ctl: ctl, conn: conn}
	go func() {
		b := make([]byte, 64<<10)
		for {
			n, err := conn.Read(b)
			if err != nil {
				return
			}
			reply(append([]byte{}, b[:n]...)) // уже в формате SOCKS5 UDP
		}
	}()
	go func() { io.Copy(io.Discard, ctl); conn.Close() }()
	return u, nil
}

func (u *upstreamUDP) send(pkt []byte) { u.conn.Write(pkt) }
func (u *upstreamUDP) close()          { u.ctl.Close(); u.conn.Close() }

// dnsServfail - ответ «сервер не смог» (приложение повторит запрос)
func dnsServfail(q []byte) []byte {
	out := append([]byte{}, q...)
	out[2] = 0x81 | (q[2] & 0x01)
	out[3] = 0x82
	for i := 6; i < 12; i++ {
		out[i] = 0
	}
	if n := doh.QuestionEnd(q); n > 0 {
		out = out[:n]
	}
	return out
}

// dnsQType - тип первого вопроса DNS-запроса (0 - не разобрать)
func dnsQType(q []byte) int {
	n := doh.QuestionEnd(q)
	if n < 16 || binary.BigEndian.Uint16(q[4:]) == 0 {
		return 0
	}
	return int(binary.BigEndian.Uint16(q[n-4:]))
}

// dnsEmpty - ответ «такое имя есть, но записей этого типа нет» (NOERROR без ответов)
func dnsEmpty(q []byte) []byte {
	out := dnsServfail(q)
	out[3] = 0x80 // RA=1, RCODE=0
	return out
}

// serveTCPDNS - DNS по TCP (длина 2 байта + запрос) через зашифрованный DNS
func (r *Router) serveTCPDNS(c net.Conn) {
	for {
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		lb := make([]byte, 2)
		if _, err := io.ReadFull(c, lb); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(lb))
		if _, err := io.ReadFull(c, q); err != nil || len(q) < 12 {
			return
		}
		r.St.DNS.Add(1)
		var resp []byte
		if !r.IPv6() && dnsQType(q) == 28 {
			r.St.AAAAEmpty.Add(1)
			resp = dnsEmpty(q)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			var err error
			resp, err = r.dns.Exchange(ctx, q)
			cancel()
			if err != nil {
				r.St.DNSFail.Add(1)
				resp = dnsServfail(q)
			}
		}
		out := make([]byte, 2, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		if _, err := c.Write(append(out, resp...)); err != nil {
			return
		}
	}
}
