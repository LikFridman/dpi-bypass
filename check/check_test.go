package check

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func server(t *testing.T, throttle bool) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><script src="/static/app.js"></script><img src="/logo.png"></head><body>hi</body></html>`)
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2000000")
		chunk := []byte(strings.Repeat("x", 16<<10))
		w.Write(chunk)
		if throttle {
			// как ТСПУ: после 16 КБ соединение рвётся
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
			if hj, ok := w.(http.Hijacker); ok {
				c, _, _ := hj.Hijack()
				if tc, ok := c.(interface{ NetConn() net.Conn }); ok {
					tc.NetConn().(*net.TCPConn).SetLinger(0)
				}
				c.Close()
			}
			return
		}
		for i := 0; i < 80; i++ {
			w.Write(chunk)
		}
	})
	s := httptest.NewUnstartedServer(mux)
	s.EnableHTTP2 = false
	s.StartTLS()
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	testRoots = pool
	return s
}

func site(s *httptest.Server) Site {
	h := strings.TrimPrefix(s.URL, "https://")
	return Site{Name: "Test", Host: h, Domains: []string{"127.0.0.1"}}
}

func TestOK(t *testing.T) {
	s := server(t, false)
	defer s.Close()
	r := Run(context.Background(), site(s), Direct(3*time.Second), Options{})
	if !r.OK || r.Bytes < 1<<20 || !strings.HasPrefix(r.What, "файл") {
		t.Fatalf("%+v", r)
	}
	r = Run(context.Background(), site(s), Direct(3*time.Second), Options{Light: true})
	if !r.OK || r.Bytes < 256<<10 {
		t.Fatalf("light: %+v", r)
	}
}

func TestThrottle(t *testing.T) {
	s := server(t, true)
	defer s.Close()
	r := Run(context.Background(), site(s), Direct(3*time.Second), Options{})
	if r.OK || r.Stage != "throttle" {
		t.Fatalf("%+v", r)
	}
}

func TestTLSReset(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// как DPI: прочитать ClientHello и сбросить соединение
			b := make([]byte, 1024)
			c.Read(b)
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
		}
	}()
	r := Run(context.Background(), Site{Name: "X", Host: ln.Addr().String()}, Direct(3*time.Second), Options{})
	if r.OK || r.Stage != "tls" {
		t.Fatalf("%+v", r)
	}
}

func TestTCPBlocked(t *testing.T) {
	r := Run(context.Background(), Site{Name: "X", Host: "127.0.0.1:1"}, Direct(2*time.Second), Options{})
	if r.OK || r.Stage != "tcp" {
		t.Fatalf("%+v", r)
	}
}
