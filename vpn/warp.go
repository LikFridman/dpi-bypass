package vpn

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// WarpAccount - бесплатная учётная запись Cloudflare WARP (WireGuard)
type WarpAccount struct {
	PrivateKey string `json:"private_key"`
	PeerKey    string `json:"peer_key"`
	V4         string `json:"v4"`
	V6         string `json:"v6"`
	Reserved   []int  `json:"reserved"`
}

// Точки входа WARP: разные адреса и порты - у провайдеров режут по-разному
var warpEndpoints = []string{"162.159.192.1:2408", "162.159.195.1:500", "188.114.97.1:4500", "162.159.192.9:1701", "188.114.98.224:854"}

// RegisterWarp создаёт учётную запись WARP. dial - как соединяться с api.cloudflareclient.com
// (его часто блокируют - тогда через обход); nil - напрямую.
func RegisterWarp(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (*WarpAccount, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{"install_id": "", "fcm_token": "", "tos": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"key": base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), "type": "Android", "locale": "en_US"})
	tr := &http.Transport{TLSHandshakeTimeout: 10 * time.Second}
	if dial != nil {
		tr.DialContext = dial
	}
	cl := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.cloudflareclient.com/v0a2158/reg", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.30-3596")
	r, err := cl.Do(req)
	if err != nil {
		return nil, shortErr(err)
	}
	defer r.Body.Close()
	b, _ := readLimited(r.Body, 1<<20)
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("WARP: HTTP %d", r.StatusCode)
	}
	var resp struct {
		Config struct {
			ClientID string `json:"client_id"`
			Peers    []struct {
				PublicKey string `json:"public_key"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	}
	if err := json.Unmarshal(b, &resp); err != nil || len(resp.Config.Peers) == 0 {
		return nil, errors.New("WARP: непонятный ответ")
	}
	a := &WarpAccount{PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes()), PeerKey: resp.Config.Peers[0].PublicKey,
		V4: resp.Config.Interface.Addresses.V4, V6: resp.Config.Interface.Addresses.V6}
	if cid, err := base64.StdEncoding.DecodeString(resp.Config.ClientID); err == nil && len(cid) == 3 {
		a.Reserved = []int{int(cid[0]), int(cid[1]), int(cid[2])}
	}
	if a.V4 == "" {
		a.V4 = "172.16.0.2"
	}
	return a, nil
}

// Links - ссылки wireguard:// на этот аккаунт: несколько точек входа, с маскировкой и без
func (a *WarpAccount) Links() []string {
	addr := a.V4 + "/32"
	if a.V6 != "" {
		addr += "," + a.V6 + "/128"
	}
	var res []string
	for _, r := range a.Reserved {
		res = append(res, fmt.Sprint(r))
	}
	var out []string
	for i, ep := range warpEndpoints {
		for _, noise := range []bool{true, false} {
			q := url.Values{"publickey": {a.PeerKey}, "address": {addr}, "mtu": {"1280"}}
			if len(res) == 3 {
				q.Set("reserved", strings.Join(res, ","))
			}
			name := fmt.Sprintf("Cloudflare WARP %d", i+1)
			if noise {
				q.Set("noise", "1")
				name += " (маскировка)"
			}
			out = append(out, "wireguard://"+url.PathEscape(a.PrivateKey)+"@"+ep+"/?"+q.Encode()+"#"+url.PathEscape(name))
		}
	}
	return out
}
