package tg

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestBridgeDirect(t *testing.T) {
	px := &TGProxy{Secret: make([]byte, 16)}
	gotFrames := make(chan int, 10)
	px.DialWS = func(dc int, media, test bool) (*wsConn, string, error) {
		if dc != 4 || !media {
			t.Errorf("DC %d media %v", dc, media)
		}
		cli, srv := net.Pipe()
		go func() {
			sw := &wsConn{c: srv, br: bufio.NewReader(srv)}
			init, err := sw.ReadMsg()
			if err != nil {
				return
			}
			dec, enc, _, _ := serverSide(t, init)
			for {
				m, err := sw.ReadMsg()
				if err != nil {
					return
				}
				gotFrames <- len(m)
				sw.WriteMsg(xorBytes(enc, xorBytes(dec, m)))
			}
		}()
		return &wsConn{c: cli, br: bufio.NewReader(cli), mask: true}, "kws4-1.web.telegram.org", nil
	}
	// клиент Telegram, подключающийся напрямую: приветствие без секрета
	init := newRelayInit(tagIntermediate, -4)
	appSide, routerSide := net.Pipe()
	go px.BridgeDirect(routerSide, init, net.ParseIP("149.154.167.91"), nil)
	// ключи клиента
	enc := ctrStream(init[8:40], init[40:56])
	enc.XORKeyStream(make([]byte, 64), make([]byte, 64))
	rev := reversed(init[8:56])
	dec := ctrStream(rev[:32], rev[32:48])
	p1, p2 := packet(40), packet(3000)
	go appSide.Write(xorBytes(enc, append(append([]byte{}, p1...), p2...)))
	appSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(p1)+len(p2))
	if _, err := io.ReadFull(appSide, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(xorBytes(dec, got), append(append([]byte{}, p1...), p2...)) {
		t.Fatal("данные искажены")
	}
	if a, b := <-gotFrames, <-gotFrames; a != len(p1) || b != len(p2) {
		t.Fatalf("кадры WebSocket %d %d", a, b)
	}
	if !IsTelegramIP(net.ParseIP("149.154.167.51")) || IsTelegramIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("IsTelegramIP")
	}
}
