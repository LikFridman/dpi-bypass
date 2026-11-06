package check

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// discordGateway: WebSocket к gateway.discord.gg и первое сообщение HELLO (op 10).
// DPI часто блокирует именно шлюз: сайт открывается, а клиент Discord висит на «Подключение».
func discordGateway(ctx context.Context, dial Dial) error {
	const host = "gateway.discord.gg"
	raw, err := dial(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	} else {
		raw.SetDeadline(time.Now().Add(10 * time.Second))
	}
	c := tls.Client(raw, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
	if err := c.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS: %w", err)
	}
	k := make([]byte, 16)
	rand.Read(k)
	fmt.Fprintf(c, "GET /?v=10&encoding=json HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: %s\r\n\r\n",
		host, base64.StdEncoding.EncodeToString(k), ua)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != 101 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil {
		return err
	}
	n := int(h[1] & 0x7f)
	if n == 126 {
		b := make([]byte, 2)
		io.ReadFull(br, b)
		n = int(b[0])<<8 | int(b[1])
	} else if n == 127 {
		return errors.New("слишком большой кадр")
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(br, p); err != nil {
		return err
	}
	if !strings.Contains(string(p), `"op":10`) {
		return errors.New("нет HELLO")
	}
	return nil
}
