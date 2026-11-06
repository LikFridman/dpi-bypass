package doh

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ответ: A 93.184.216.34, TTL 120
func answer(q []byte) []byte {
	end, _ := skipName(q, 12)
	m := append([]byte{}, q[:end+4]...)
	m[2], m[3] = 0x81, 0x80
	binary.BigEndian.PutUint16(m[6:], 1)
	m = append(m, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 93, 184, 216, 34)
	return m
}

func testServer(t *testing.T, hits *int64) *Resolver {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(hits, 1)
		q, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/dns-message" || binary.BigEndian.Uint16(q[:2]) != 0 {
			w.WriteHeader(400)
			return
		}
		w.Write(answer(q))
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	old := Endpoints
	Endpoints = []string{"https://127.0.0.1:1/dns-query", "https://" + addr + "/dns-query"}
	t.Cleanup(func() { Endpoints = old })
	testRoots = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	t.Cleanup(func() { testRoots = nil })
	return New(nil, nil)
}

func TestExchangeCacheAndID(t *testing.T) {
	var hits int64
	r := testServer(t, &hits)
	q := BuildQuery("Example.COM", 1)
	q[0], q[1] = 0xAB, 0xCD
	m, err := r.Exchange(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if m[0] != 0xAB || m[1] != 0xCD {
		t.Fatalf("ID не восстановлен: %x", m[:2])
	}
	ips := ParseIPs(m)
	if len(ips) != 1 || ips[0].String() != "93.184.216.34" {
		t.Fatalf("адреса: %v", ips)
	}
	q2 := BuildQuery("example.com", 1)
	q2[0], q2[1] = 1, 2
	m2, err := r.Exchange(context.Background(), q2)
	if err != nil || m2[0] != 1 || m2[1] != 2 {
		t.Fatalf("кеш: %v %x", err, m2[:2])
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("ожидался 1 запрос к серверу (второй из кеша), было %d", hits)
	}
	if d := minTTL(m); d != 120*time.Second {
		t.Fatalf("TTL %v", d)
	}
}

func TestServeUDPAndWrap(t *testing.T) {
	var hits int64
	r := testServer(t, &hits)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go r.ServeUDP(pc)
	c, _ := net.Dial("udp", pc.LocalAddr().String())
	defer c.Close()
	c.Write(BuildQuery("udp.test", 1))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil || len(ParseIPs(buf[:n])) != 1 {
		t.Fatalf("UDP: %v %x", err, buf[:n])
	}
	// Wrap подставляет адрес из DoH
	var got string
	d := r.Wrap(func(ctx context.Context, network, addr string) (net.Conn, error) {
		got = addr
		return nil, io.EOF
	})
	d(context.Background(), "tcp", "site.test:443")
	if got != "93.184.216.34:443" {
		t.Fatalf("Wrap: %q", got)
	}
	_, ip := d(context.Background(), "tcp", "1.2.3.4:80")
	if got != "1.2.3.4:80" || ip == nil {
		t.Fatalf("IP-адрес должен идти как есть: %q", got)
	}
}

func TestServfailWhenDown(t *testing.T) {
	old := Endpoints
	Endpoints = []string{"https://127.0.0.1:1/dns-query"}
	defer func() { Endpoints = old }()
	r := New(nil, nil)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	go r.ServeUDP(pc)
	c, _ := net.Dial("udp", pc.LocalAddr().String())
	c.Write(BuildQuery("down.test", 1))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil || buf[3]&0x0F != 2 {
		t.Fatalf("ожидался SERVFAIL: %v %x", err, buf[:n])
	}
	if !strings.Contains(r.Stats.LastError, "DoH") {
		t.Fatalf("ошибка: %q", r.Stats.LastError)
	}
}
