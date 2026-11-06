package router

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// sniffHost достаёт имя сайта из начала соединения: SNI из TLS ClientHello
// или Host из HTTP-запроса. more=true - данных не хватает, стоит дочитать.
func sniffHost(b []byte) (host string, more bool) {
	if len(b) == 0 {
		return "", true
	}
	if b[0] == 0x16 { // TLS handshake
		return parseSNI(b)
	}
	for _, m := range []string{"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "CONNECT ", "DELETE ", "PATCH "} {
		if bytes.HasPrefix(b, []byte(m)) {
			end := bytes.Index(b, []byte("\r\n\r\n"))
			for _, line := range strings.Split(string(b), "\r\n") {
				if len(line) > 5 && strings.EqualFold(line[:5], "host:") {
					h := strings.TrimSpace(line[5:])
					if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
						h = h[:i]
					}
					return strings.ToLower(h), false
				}
			}
			return "", end < 0 && len(b) < 8192
		}
	}
	return "", false
}

func parseSNI(b []byte) (string, bool) {
	if len(b) < 5 {
		return "", true
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+recLen {
		// ClientHello может прийти в нескольких сегментах
		return "", len(b) < 16384+5
	}
	p := b[5 : 5+recLen]
	if len(p) < 4 || p[0] != 1 {
		return "", false
	}
	p = p[4:]
	if len(p) < 34 {
		return "", false
	}
	p = p[34:] // version + random
	if len(p) < 1 || len(p) < 1+int(p[0]) {
		return "", false
	}
	p = p[1+int(p[0]):] // session id
	if len(p) < 2 {
		return "", false
	}
	cs := int(binary.BigEndian.Uint16(p))
	if len(p) < 2+cs+1 {
		return "", false
	}
	p = p[2+cs:]
	cm := int(p[0])
	if len(p) < 1+cm+2 {
		return "", false
	}
	p = p[1+cm:]
	el := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < el {
		return "", false
	}
	p = p[:el]
	for len(p) >= 4 {
		typ := binary.BigEndian.Uint16(p)
		l := int(binary.BigEndian.Uint16(p[2:]))
		if len(p) < 4+l {
			return "", false
		}
		if typ == 0 { // server_name
			d := p[4 : 4+l]
			if len(d) < 5 {
				return "", false
			}
			nl := int(binary.BigEndian.Uint16(d[3:5]))
			if d[2] == 0 && len(d) >= 5+nl {
				return strings.ToLower(string(d[5 : 5+nl])), false
			}
			return "", false
		}
		p = p[4+l:]
	}
	return "", false
}

// matchDomain: host совпадает с доменом или его поддоменом
func matchDomain(host string, domains []string) bool {
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
