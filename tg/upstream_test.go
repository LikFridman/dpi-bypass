package tg

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

func TestParseUpstream(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	dom := hex.EncodeToString([]byte("www.google.com"))
	cases := []struct {
		link, kind, addr, domain string
	}{
		{"tg://proxy?server=1.2.3.4&port=443&secret=" + key, "mtproto", "1.2.3.4:443", ""},
		{"https://t.me/proxy?server=p.example.org&port=8443&secret=dd" + key, "mtproto", "p.example.org:8443", ""},
		{"tg://proxy?server=5.6.7.8&port=443&secret=ee" + key + dom, "mtproto", "5.6.7.8:443", "www.google.com"},
		{"socks5://10.0.0.1:1080", "socks5", "10.0.0.1:1080", ""},
		{"tg://socks?server=10.0.0.2&port=9050", "socks5", "10.0.0.2:9050", ""},
	}
	for _, c := range cases {
		u, err := ParseUpstream(c.link)
		if err != nil || u.Kind != c.kind || u.Addr != c.addr || u.Domain != c.domain {
			t.Fatalf("%s: %+v %v", c.link, u, err)
		}
		if u.Kind == "mtproto" && hex.EncodeToString(u.Key) != key {
			t.Fatalf("%s: ключ %x", c.link, u.Key)
		}
	}
	for _, bad := range []string{"", "http://x", "tg://proxy?server=1.2.3.4", "tg://proxy?server=1.2.3.4&secret=zz"} {
		if _, err := ParseUpstream(bad); err == nil {
			t.Fatalf("%q должна отклоняться", bad)
		}
	}
}

// fakeMTProxy - внешний MTProto-прокси с FakeTLS (или без): принимает obfuscated2
// с секретом key, проверяет DC и отвечает эхом.
func fakeMTProxy(t *testing.T, key []byte, fakeTLS bool, gotDC chan<- int16) net.Listener {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		var r io.Reader = s
		var w io.Writer = s
		if fakeTLS {
			_, hello, err := readTLSRecord(s)
			if err != nil {
				return
			}
			got := append([]byte{}, hello[11:43]...)
			z := append([]byte{}, hello...)
			for i := 11; i < 43; i++ {
				z[i] = 0
			}
			m := hmac.New(sha256.New, key)
			m.Write(z)
			want := m.Sum(nil)
			if !bytes.Equal(want[:28], got[:28]) {
				t.Error("FakeTLS: неверный HMAC в ClientHello")
				return
			}
			ts := binary.LittleEndian.Uint32(got[28:]) ^ binary.LittleEndian.Uint32(want[28:])
			if d := time.Now().Unix() - int64(ts); d < -5 || d > 5 {
				t.Errorf("FakeTLS: время %d", d)
			}
			sh := append([]byte{0x16, 3, 3, 0, 42, 2, 0, 0, 38, 3, 3}, make([]byte, 32)...)
			sh = append(sh, 0, 0x13, 1, 0)
			sh[4] = byte(len(sh) - 5)
			resp := append(sh, 0x14, 3, 3, 0, 1, 1, 0x17, 3, 3, 0, 4, 1, 2, 3, 4)
			m = hmac.New(sha256.New, key)
			m.Write(got)
			m.Write(resp)
			copy(resp[11:43], m.Sum(nil))
			s.Write(resp)
			pr, pw := io.Pipe()
			go func() {
				for {
					typ, rec, err := readTLSRecord(s)
					if err != nil {
						pw.CloseWithError(err)
						return
					}
					if typ == 0x17 {
						pw.Write(rec[5:])
					}
				}
			}()
			r = pr
			w = &fakeTLSConn{Conn: s, sentCC: true}
		}
		init := make([]byte, 64)
		if _, err := io.ReadFull(r, init); err != nil {
			return
		}
		dec := ctrStream(withSecret(init[8:40], key), init[40:56])
		plain := xorBytes(dec, init)
		gotDC <- int16(binary.LittleEndian.Uint16(plain[60:62]))
		rev := reversed(init[8:56])
		enc := ctrStream(withSecret(rev[:32], key), rev[32:48])
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if err != nil {
				return
			}
			w.Write(xorBytes(enc, xorBytes(dec, buf[:n])))
		}
	}()
	return ln
}

func TestUpstreamMTProxy(t *testing.T) {
	for _, fakeTLS := range []bool{false, true} {
		key := make([]byte, 16)
		rand.Read(key)
		gotDC := make(chan int16, 1)
		ln := fakeMTProxy(t, key, fakeTLS, gotDC)
		link := "tg://proxy?server=127.0.0.1&port=" + portOf(ln) + "&secret=dd" + hex.EncodeToString(key)
		if fakeTLS {
			link = "tg://proxy?server=127.0.0.1&port=" + portOf(ln) + "&secret=ee" + hex.EncodeToString(key) + hex.EncodeToString([]byte("www.google.com"))
		}
		up, err := ParseUpstream(link)
		if err != nil {
			t.Fatal(err)
		}
		secret := make([]byte, 16)
		rand.Read(secret)
		px := &TGProxy{Secret: secret}
		px.Routes = func() []TGRoute {
			return []TGRoute{{Name: "сломан", TCP: func(int) (net.Conn, string, error) { return nil, "", io.EOF }}, up.Route()}
		}
		px.Listen("127.0.0.1:0")
		c, _ := net.Dial("tcp", px.Addr())
		fd := newFakeDesktop(secret, tagSecure, -2)
		msg := packet(300)
		c.Write(fd.init)
		c.Write(xorBytes(fd.enc, msg))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("fakeTLS=%v: %v", fakeTLS, err)
		}
		if !bytes.Equal(xorBytes(fd.dec, got), msg) {
			t.Fatalf("fakeTLS=%v: данные искажены", fakeTLS)
		}
		if dc := <-gotDC; dc != -2 {
			t.Fatalf("fakeTLS=%v: DC %d", fakeTLS, dc)
		}
		c.Close()
		px.Close()
		ln.Close()
	}
}

func portOf(ln net.Listener) string {
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p
}

func TestFakeTLSHelloSize(t *testing.T) {
	h := fakeTLSHello(make([]byte, 16), "www.google.com", time.Now())
	if len(h) != 517 || h[0] != 0x16 || h[5] != 1 {
		t.Fatalf("ClientHello: длина %d", len(h))
	}
}

// TestCheckLocal - Check через прокси с поддельным сервером Telegram, отвечающим resPQ
func TestCheckLocal(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)
	px := &TGProxy{Secret: secret}
	px.Routes = func() []TGRoute {
		return []TGRoute{{Name: "fake DC", TCP: func(int) (net.Conn, string, error) {
			cli, srv := net.Pipe()
			go func() {
				init := make([]byte, 64)
				io.ReadFull(srv, init)
				dec, enc, _, _ := serverSide(t, init)
				h := make([]byte, 4)
				io.ReadFull(srv, h)
				n := binary.LittleEndian.Uint32(xorBytes(dec, h))
				m := xorBytes(dec, func() []byte { b := make([]byte, n); io.ReadFull(srv, b); return b }())
				resp := make([]byte, 40+12)
				binary.LittleEndian.PutUint32(resp[20:], 0x05162463)
				copy(resp[24:40], m[24:40])
				out := make([]byte, 4+len(resp))
				binary.LittleEndian.PutUint32(out, uint32(len(resp)))
				copy(out[4:], resp)
				srv.Write(xorBytes(enc, out))
			}()
			return cli, "", nil
		}}}
	}
	px.Listen("127.0.0.1:0")
	defer px.Close()
	if _, err := Check(px.Addr(), secret, 2); err != nil {
		t.Fatal(err)
	}
}
