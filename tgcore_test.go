package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeDesktop имитирует Telegram Desktop, подключённый к MTProto-прокси с секретом.
type fakeDesktop struct {
	init     []byte
	enc, dec interface{ XORKeyStream(dst, src []byte) }
}

func newFakeDesktop(secret, tag []byte, dc int16) *fakeDesktop {
	rnd := make([]byte, 64)
	rand.Read(rnd)
	rnd[0] = 0x11
	copy(rnd[56:60], tag)
	binary.LittleEndian.PutUint16(rnd[60:62], uint16(dc))
	key := withSecret(rnd[8:40], secret)
	enc := ctrStream(key, rnd[40:56])
	encInit := xorBytes(enc, rnd)
	init := append(append([]byte{}, rnd[:56]...), encInit[56:]...)
	rev := reversed(rnd[8:56])
	return &fakeDesktop{init: init, enc: enc, dec: ctrStream(withSecret(rev[:32], secret), rev[32:48])}
}

func TestParseClientInit(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)
	cases := []struct {
		dc            int16
		wantDC        int
		media, isTest bool
	}{{2, 2, false, false}, {-4, 4, true, false}, {10001, 1, false, true}, {-10003, 3, true, true}}
	for _, c := range cases {
		fd := newFakeDesktop(secret, tagSecure, c.dc)
		ci, ok := parseClientInit(fd.init, secret)
		if !ok || ci.DC != c.wantDC || ci.Media != c.media || ci.Test != c.isTest || !bytesEq(ci.Tag, tagSecure) {
			t.Fatalf("dc=%d: got %+v ok=%v", c.dc, ci, ok)
		}
	}
	other := make([]byte, 16)
	if _, ok := parseClientInit(newFakeDesktop(secret, tagSecure, 2).init, other); ok {
		t.Fatal("чужой секрет должен отклоняться")
	}
}

// serverSide - ключи сервера Telegram для приветствия obfuscated2 без секрета
func serverSide(t *testing.T, init []byte) (dec, enc interface{ XORKeyStream(dst, src []byte) }, tag []byte, dc int16) {
	d := ctrStream(init[8:40], init[40:56])
	plain := xorBytes(d, init)
	rev := reversed(init[8:56])
	return d, ctrStream(rev[:32], rev[32:48]), plain[56:60], int16(binary.LittleEndian.Uint16(plain[60:62]))
}

func TestRelayInit(t *testing.T) {
	for _, dc := range []int16{2, -5, 10002} {
		init := newRelayInit(tagIntermediate, dc)
		_, _, tag, got := serverSide(t, init)
		if !bytesEq(tag, tagIntermediate) || got != dc {
			t.Fatalf("dc=%d: tag=%x got=%d", dc, tag, got)
		}
	}
}

func packet(n int) []byte {
	p := make([]byte, 4+n)
	binary.LittleEndian.PutUint32(p, uint32(n))
	rand.Read(p[4:])
	return p
}

func TestProxyEndToEnd(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	var frames [][]byte
	var fmu sync.Mutex
	serverErr := make(chan error, 1)

	px := &TGProxy{Secret: secret}
	px.DialWS = func(dc int, media, test bool) (*wsConn, string, error) {
		if dc != 2 || media || test {
			t.Errorf("неверный DC: %d %v %v", dc, media, test)
		}
		cli, srv := net.Pipe()
		go func() { // поддельный сервер Telegram за WebSocket: эхо каждого пакета
			sw := &wsConn{c: srv, br: bufio.NewReader(srv), mask: false}
			init, err := sw.ReadMsg()
			if err != nil || len(init) != 64 {
				serverErr <- io.ErrUnexpectedEOF
				return
			}
			dec, enc, tag, gotDC := serverSide(t, init)
			if !bytesEq(tag, tagSecure) || gotDC != 2 {
				t.Errorf("сервер получил tag=%x dc=%d", tag, gotDC)
			}
			for {
				m, err := sw.ReadMsg()
				if err != nil {
					serverErr <- nil
					return
				}
				plain := xorBytes(dec, m)
				fmu.Lock()
				frames = append(frames, plain)
				fmu.Unlock()
				if err := sw.WriteMsg(xorBytes(enc, plain)); err != nil {
					serverErr <- err
					return
				}
			}
		}()
		return &wsConn{c: cli, br: bufio.NewReader(cli), mask: true}, "kws2.web.telegram.org", nil
	}
	if err := px.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer px.Close()

	c, err := net.Dial("tcp", px.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fd := newFakeDesktop(secret, tagSecure, 2)
	p1, p2, p3 := packet(20), packet(100), packet(70000)
	want := append(append(append([]byte{}, p1...), p2...), p3...)

	go func() {
		c.Write(fd.init)
		c.Write(xorBytes(fd.enc, append(append([]byte{}, p1...), p2...))) // два пакета одним куском
		e3 := xorBytes(fd.enc, p3)
		c.Write(e3[:3]) // пакет по частям
		time.Sleep(50 * time.Millisecond)
		c.Write(e3[3:40000])
		time.Sleep(50 * time.Millisecond)
		c.Write(e3[40000:])
	}()

	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("чтение ответа: %v", err)
	}
	plain := xorBytes(fd.dec, got)
	if !bytes.Equal(plain, want) {
		t.Fatal("ответ сервера расшифровался неверно")
	}
	fmu.Lock()
	defer fmu.Unlock()
	if len(frames) != 3 || !bytes.Equal(frames[0], p1) || !bytes.Equal(frames[1], p2) || !bytes.Equal(frames[2], p3) {
		t.Fatalf("сервер должен получить ровно 3 целых пакета, получил %d кадров", len(frames))
	}
	if _, _, ws, _, _ := px.Stats(); ws != 1 {
		t.Fatalf("ожидалось 1 соединение через WebSocket, было %d", ws)
	}
}

func TestFallbackTCP(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)
	px := &TGProxy{Secret: secret}
	px.DialWS = func(int, bool, bool) (*wsConn, string, error) { return nil, "", io.EOF }
	px.DialTCP = func(dc int) (net.Conn, error) {
		cli, srv := net.Pipe()
		go func() {
			init := make([]byte, 64)
			io.ReadFull(srv, init)
			dec, enc, _, _ := serverSide(t, init)
			buf := make([]byte, 4096)
			for {
				n, err := srv.Read(buf)
				if err != nil {
					return
				}
				srv.Write(xorBytes(enc, xorBytes(dec, buf[:n])))
			}
		}()
		return cli, nil
	}
	px.Listen("127.0.0.1:0")
	defer px.Close()
	c, _ := net.Dial("tcp", px.Addr())
	defer c.Close()
	fd := newFakeDesktop(secret, tagAbridged, -3)
	msg := []byte{0x02, 1, 2, 3, 4, 5, 6, 7, 8}
	c.Write(fd.init)
	c.Write(xorBytes(fd.enc, msg))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(xorBytes(fd.dec, got), msg) {
		t.Fatal("прямое соединение: данные искажены")
	}
}

func TestSplitterAbridged(t *testing.T) {
	sp := newSplitter(tagAbridged)
	big := append([]byte{0x7f, 0x02, 0x00, 0x00}, make([]byte, 8)...) // длинная форма: 2*4 байт
	small := []byte{0x01, 9, 9, 9, 9}
	all := append(append([]byte{}, small...), big...)
	parts := sp.split(all, all)
	if len(parts) != 2 || len(parts[0]) != 5 || len(parts[1]) != 12 {
		t.Fatalf("abridged: %d частей", len(parts))
	}
}

func TestSocksRoute(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)
	// поддельный SOCKS5 VPN-клиента, за которым "сервер Telegram"
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	gotTarget := make(chan string, 1)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		g := make([]byte, 3)
		io.ReadFull(s, g)
		s.Write([]byte{5, 0})
		h := make([]byte, 4)
		io.ReadFull(s, h)
		ip := make([]byte, 4)
		io.ReadFull(s, ip)
		pb := make([]byte, 2)
		io.ReadFull(s, pb)
		gotTarget <- net.JoinHostPort(net.IP(ip).String(), "443")
		s.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		init := make([]byte, 64)
		io.ReadFull(s, init)
		dec, enc, _, _ := serverSide(t, init)
		buf := make([]byte, 4096)
		for {
			n, err := s.Read(buf)
			if err != nil {
				return
			}
			s.Write(xorBytes(enc, xorBytes(dec, buf[:n])))
		}
	}()
	px := &TGProxy{Secret: secret}
	px.Routes = func() []TGRoute {
		return []TGRoute{
			{Name: "сломан", TCP: func(int) (net.Conn, string, error) { return nil, "", io.EOF }},
			SocksRoute("через VPN", ln.Addr().String()),
		}
	}
	px.Listen("127.0.0.1:0")
	defer px.Close()
	c, _ := net.Dial("tcp", px.Addr())
	defer c.Close()
	fd := newFakeDesktop(secret, tagIntermediate, 4)
	msg := packet(50)
	c.Write(fd.init)
	c.Write(xorBytes(fd.enc, msg))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(xorBytes(fd.dec, got), msg) {
		t.Fatal("SOCKS: данные искажены")
	}
	if tgt := <-gotTarget; tgt != "149.154.167.91:443" {
		t.Fatalf("SOCKS CONNECT не к DC4: %s", tgt)
	}
}

func TestValidStrategy(t *testing.T) {
	ok := []Strategy{
		{"a", "x", []string{"--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com"}},
		{"b", "x", []string{"--dpi-desync=fake", "--dpi-desync-fake-tls=0x16030100"}},
	}
	bad := []Strategy{
		{"c", "x", []string{"--wf-raw=@C:\\evil.txt"}},
		{"d", "x", []string{"--dpi-desync-fake-tls=C:/file.bin"}},
		{"e", "x", []string{"--dpi-desync=fake --hostlist=x"}},
		{"f", "x", []string{"--dpi-desync-fake-quic=..\\a"}},
		{"g", "x", nil},
	}
	for _, s := range ok {
		if !validStrategy(s) {
			t.Errorf("должна пройти: %v", s.Args)
		}
	}
	for _, s := range bad {
		if validStrategy(s) {
			t.Errorf("должна быть отклонена: %v", s.Args)
		}
	}
}

// update/update.json из репозитория должен проходить проверку, иначе программа его отбросит
func TestUpdateFileValid(t *testing.T) {
	b, err := os.ReadFile("update/update.json")
	if err != nil {
		t.Skip("нет update/update.json")
	}
	var ru struct {
		Strategies []Strategy `json:"strategies"`
		Services   []string   `json:"services"`
	}
	if err := json.Unmarshal(b, &ru); err != nil {
		t.Fatal(err)
	}
	for _, s := range ru.Strategies {
		if !validStrategy(s) {
			t.Errorf("стратегия %q не проходит проверку", s.ID)
		}
	}
	for _, l := range ru.Services {
		if len(strings.Split(l, "|")) < 2 {
			t.Errorf("неверная строка сервиса: %q", l)
		}
	}
}
