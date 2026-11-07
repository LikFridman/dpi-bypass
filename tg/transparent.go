package tg

// Прозрачный режим: приложение Telegram подключается напрямую к серверу DC
// (obfuscated2 без секрета), а мы, не меняя ни байта, переносим этот поток в
// WebSocket к kwsN.web.telegram.org. Так Telegram работает, даже если IP его
// серверов недоступны, без настройки прокси в самом приложении.

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// DirectInit - разобранное приветствие прямого (без прокси) подключения Telegram.
type DirectInit struct {
	DC    int
	Media bool
	Test  bool
	Tag   []byte
}

// ParseDirectInit разбирает 64-байтное приветствие obfuscated2 без секрета.
// ok=false - это не obfuscated2 (например, незашифрованный abridged), такой поток не трогаем.
func ParseDirectInit(init []byte) (DirectInit, bool) {
	var r DirectInit
	if len(init) != tgHandshakeLen || init[0] == 0xef {
		return r, false
	}
	dec := xorBytes(ctrStream(init[tgSkipLen:tgSkipLen+tgPrekeyLen], init[tgSkipLen+tgPrekeyLen:tgSkipLen+tgPrekeyLen+tgIVLen]), init)
	tag := dec[tgTagPos : tgTagPos+4]
	if !bytesEq(tag, tagAbridged) && !bytesEq(tag, tagIntermediate) && !bytesEq(tag, tagSecure) {
		return r, false
	}
	idx := int(int16(binary.LittleEndian.Uint16(dec[tgDCPos : tgDCPos+2])))
	r.Tag = append([]byte{}, tag...)
	if idx < 0 {
		r.Media, idx = true, -idx
	}
	if idx >= 10000 {
		r.Test, idx = true, idx-10000
	}
	r.DC = idx
	return r, true
}

// Диапазоны адресов серверов Telegram (AS62041, AS59930, AS62014, AS211157)
var tgNets = []netip.Prefix{
	netip.MustParsePrefix("149.154.160.0/20"),
	netip.MustParsePrefix("91.108.4.0/22"),
	netip.MustParsePrefix("91.108.8.0/22"),
	netip.MustParsePrefix("91.108.12.0/22"),
	netip.MustParsePrefix("91.108.16.0/22"),
	netip.MustParsePrefix("91.108.20.0/22"),
	netip.MustParsePrefix("91.108.56.0/22"),
	netip.MustParsePrefix("91.105.192.0/23"),
	netip.MustParsePrefix("95.161.64.0/20"),
	netip.MustParsePrefix("185.76.151.0/24"),
	netip.MustParsePrefix("2001:67c:4e8::/48"),
	netip.MustParsePrefix("2001:b28:f23c::/46"),
	netip.MustParsePrefix("2a0a:f280::/32"),
}

// IsTelegramIP - адрес принадлежит серверам Telegram
func IsTelegramIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	for _, p := range tgNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// dcByIP - номер DC по адресу (если клиент не указал его в приветствии)
func dcByIP(ip net.IP) int {
	v4 := ip.To4()
	if v4 == nil {
		return 2
	}
	switch {
	case v4[0] == 149 && v4[1] == 154 && v4[2] == 175 && v4[3] < 100:
		return 1
	case v4[0] == 149 && v4[1] == 154 && v4[2] == 175:
		return 3
	case v4[0] == 149 && v4[1] == 154 && v4[2] == 167 && v4[3] >= 90 && v4[3] < 100:
		return 4
	case v4[0] == 149 && v4[1] == 154 && (v4[2] == 171 || v4[2] == 165):
		return 5
	case v4[0] == 91 && v4[1] == 108 && v4[2] >= 56 && v4[2] < 60:
		return 5
	case v4[0] == 91 && v4[1] == 108 && v4[2] >= 8 && v4[2] < 12:
		return 4
	case v4[0] == 91 && v4[1] == 108 && v4[2] >= 4 && v4[2] < 8:
		return 3
	default:
		return 2
	}
}

// BridgeDirect переносит прямое подключение Telegram (init уже прочитан) в WebSocket.
// dial - как соединяться с web.telegram.org (например, через SOCKS обхода).
// Возвращает false, если WebSocket открыть не удалось (клиент ещё не получил ни байта).
func (p *TGProxy) BridgeDirect(c net.Conn, init []byte, dst net.IP, dial func(addr string) (net.Conn, error)) bool {
	di, ok := ParseDirectInit(init)
	if !ok {
		return false
	}
	dc := di.DC
	if dc < 1 || dc > 5 {
		dc = dcByIP(dst)
	}
	var ws *wsConn
	var host string
	var err error
	if p.DialWS != nil {
		ws, host, err = p.DialWS(dc, di.Media, di.Test)
	} else {
		ws, host, err = p.dialWSVia(dc, di.Media, di.Test, dial)
	}
	if err != nil {
		p.logOnce("tdfail"+host, "Telegram DC%d: WebSocket не открылся (%s)", dc, shortErrMsg(err))
		return false
	}
	p.logOnce("tdok"+host, "Telegram DC%d: прямое подключение переведено в WebSocket %s", dc, host)
	p.viaWS.Add(1)
	if err := ws.WriteMsg(init); err != nil {
		ws.Close()
		return true
	}
	// клиент -> WS: расшифровываем копию только чтобы найти границы пакетов, шлём как есть
	dec := ctrStream(init[tgSkipLen:tgSkipLen+tgPrekeyLen], init[tgSkipLen+tgPrekeyLen:tgSkipLen+tgPrekeyLen+tgIVLen])
	dec.XORKeyStream(make([]byte, tgHandshakeLen), make([]byte, tgHandshakeLen))
	sp := newSplitter(di.Tag)
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 64<<10)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				raw := append([]byte{}, buf[:n]...)
				for _, part := range sp.split(raw, xorBytes(dec, raw)) {
					if ws.WriteMsg(part) != nil {
						return
					}
				}
			}
			if err != nil {
				if t := sp.flush(); len(t) > 0 {
					ws.WriteMsg(t)
				}
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			m, err := ws.ReadMsg()
			if err != nil {
				return
			}
			if _, err := c.Write(m); err != nil {
				return
			}
		}
	}()
	<-done
	ws.Close()
	return true
}

// BridgeDirectRelay переносит прямое подключение Telegram (init уже прочитан) во внешний
// MTProto-прокси: поток расшифровывается ключами приложения и шифруется ключами прокси.
// false - прокси не ответил (клиент ещё не получил ни байта, можно пробовать другой путь).
func (p *TGProxy) BridgeDirectRelay(c net.Conn, init []byte, dst net.IP, u Upstream) bool {
	di, ok := ParseDirectInit(init)
	if !ok {
		return false
	}
	dc := di.DC
	if dc < 1 || dc > 5 {
		if dc != 203 {
			dc = dcByIP(dst)
		}
	}
	idx := dc
	if di.Test {
		idx += 10000
	}
	if di.Media {
		idx = -idx
	}
	r := u.Route()
	tc, _, err := r.TCP(dc)
	if err != nil {
		p.logOnce("relayfail"+u.Addr, "Telegram: прокси %s не отвечает (%s)", u.Addr, shortErrMsg(err))
		return false
	}
	defer tc.Close()
	ri := newRelayInit(di.Tag, int16(idx), r.RelaySecret)
	cr := newTGCrypto(init, nil, ri, r.RelaySecret)
	if _, err := tc.Write(ri); err != nil {
		return false
	}
	p.logOnce("relayok"+u.Addr, "Telegram DC%d: прямое подключение переведено в прокси %s", dc, u.Addr)
	p.viaTCP.Add(1)
	p.bridgeTCP(c, tc, cr)
	return true
}
