package tg

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// Check подключается к локальному прокси как Telegram и отправляет серверу DC
// первый запрос протокола (req_pq_multi). Если сервер Telegram ответил (resPQ),
// значит связь с Telegram через прокси работает. Возвращает время ответа.
func Check(proxyAddr string, secret []byte, dc int) (time.Duration, error) {
	return CheckTimeout(proxyAddr, secret, dc, 20*time.Second)
}

// CheckTimeout - то же, что Check, с общим ограничением по времени.
func CheckTimeout(proxyAddr string, secret []byte, dc int, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))

	rnd := make([]byte, tgHandshakeLen)
	for {
		rand.Read(rnd)
		if rnd[0] != 0xef && binary.LittleEndian.Uint32(rnd[4:8]) != 0 {
			break
		}
	}
	copy(rnd[tgTagPos:], tagIntermediate)
	binary.LittleEndian.PutUint16(rnd[tgDCPos:], uint16(dc))
	enc := ctrStream(withSecret(rnd[8:40], secret), rnd[40:56])
	encInit := xorBytes(enc, rnd)
	init := append(append([]byte{}, rnd[:56]...), encInit[56:]...)
	rev := reversed(rnd[8:56])
	dec := ctrStream(withSecret(rev[:32], secret), rev[32:48])

	// незашифрованное сообщение: auth_key_id=0, message_id, длина, req_pq_multi + nonce
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body, 0xbe7e8ef1)
	rand.Read(body[4:])
	msg := make([]byte, 20+len(body))
	binary.LittleEndian.PutUint64(msg[8:], uint64(time.Now().Unix())<<32&^3)
	binary.LittleEndian.PutUint32(msg[16:], uint32(len(body)))
	copy(msg[20:], body)
	pkt := make([]byte, 4+len(msg))
	binary.LittleEndian.PutUint32(pkt, uint32(len(msg)))
	copy(pkt[4:], msg)

	if _, err := c.Write(append(init, xorBytes(enc, pkt)...)); err != nil {
		return 0, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return 0, errors.New("Telegram не ответил")
	}
	n := binary.LittleEndian.Uint32(xorBytes(dec, hdr))
	if n < 24 || n > 4096 {
		return 0, errors.New("странный ответ")
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(c, resp); err != nil {
		return 0, err
	}
	resp = xorBytes(dec, resp)
	if binary.LittleEndian.Uint32(resp[20:24]) != 0x05162463 {
		return 0, errors.New("ответ не resPQ")
	}
	if string(resp[24:40]) != string(body[4:20]) {
		return 0, errors.New("nonce не совпал")
	}
	return time.Since(start), nil
}

// CheckDC проверяет Telegram так же, как подключается приложение: obfuscated2 напрямую
// к серверу DC (через dial - например, через SOCKS обхода) и запрос req_pq.
func CheckDC(dial func(addr string) (net.Conn, error), dc int, timeout time.Duration) (time.Duration, error) {
	secret := make([]byte, 16)
	rand.Read(secret)
	px := &TGProxy{Secret: secret}
	route := TGRoute{Name: "DC", TCP: func(d int) (net.Conn, string, error) {
		c, err := dial(tgDCAddr(d))
		return c, "", err
	}}
	px.Routes = func() []TGRoute { return []TGRoute{route} }
	if err := px.Listen("127.0.0.1:0"); err != nil {
		return 0, err
	}
	defer px.Close()
	return CheckTimeout(px.Addr(), secret, dc, timeout)
}

// CheckWS - путь, которым Telegram реально работает через обход: WebSocket к web.telegram.org
// (TLS, его и маскирует стратегия), затем MTProto-запрос req_pq к DC2 через него.
// dial - как соединяться (напрямую, через SOCKS byedpi и т.п.). Возвращает время ответа сервера Telegram.
func CheckWS(dial func(addr string) (net.Conn, error), timeout time.Duration) (time.Duration, error) {
	px := &TGProxy{Secret: make([]byte, 16)}
	route := TGRoute{Name: "WebSocket", WS: func(dc int, media, test bool) (*wsConn, string, error) {
		return px.dialWSVia(dc, media, test, dial)
	}}
	px.Routes = func() []TGRoute { return []TGRoute{route} }
	if err := px.Listen("127.0.0.1:0"); err != nil {
		return 0, err
	}
	defer px.Close()
	return CheckTimeout(px.Addr(), px.Secret, 2, timeout)
}
