package check

import (
	"context"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TLS как у Chrome (и у приложения YouTube на Android, Cronet): тот же ClientHello - размер,
// порядок расширений, GREASE, ключ X25519MLKEM768. DPI смотрит именно на него, и проверка обычным
// TLS из Go могла проходить там, где настоящее приложение не грузилось (и наоборот).

// chromeConn - рукопожатие TLS с ClientHello Chrome поверх готового соединения.
// h1 - только HTTP/1.1 (для нашего HTTP-клиента), иначе h2 и http/1.1, как у браузера.
func chromeConn(ctx context.Context, c net.Conn, name string, h1 bool) (net.Conn, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return nil, err
	}
	if h1 {
		for _, e := range spec.Extensions {
			switch x := e.(type) {
			case *utls.ALPNExtension:
				x.AlpnProtocols = []string{"http/1.1"}
			case *utls.ApplicationSettingsExtension:
				x.SupportedProtocols = []string{"http/1.1"}
			case *utls.ApplicationSettingsExtensionNew:
				x.SupportedProtocols = []string{"http/1.1"}
			}
		}
	}
	u := utls.UClient(c, &utls.Config{ServerName: name, RootCAs: testRoots}, utls.HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	if err := u.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	return u, nil
}

// dialChrome - для http.Transport: соединение через dial и TLS как у Chrome (HTTP/1.1)
func dialChrome(dial Dial) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		name, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		dl := time.Now().Add(7 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(dl) {
			dl = d
		}
		c.SetDeadline(dl)
		hctx, cancel := context.WithDeadline(ctx, dl)
		defer cancel()
		tc, err := chromeConn(hctx, c, name, true)
		if err != nil {
			c.Close()
			return nil, err
		}
		c.SetDeadline(time.Time{})
		return tc, nil
	}
}

// ChromeHandshake - рукопожатие TLS как у Chrome (для проверок способов в маршрутизаторе)
func ChromeHandshake(ctx context.Context, c net.Conn, name string) error {
	_, err := chromeConn(ctx, c, name, false)
	return err
}

// ChromeClient - TLS как у Chrome поверх соединения c; h1 - договориться только о HTTP/1.1
func ChromeClient(ctx context.Context, c net.Conn, name string, h1 bool) (net.Conn, error) {
	return chromeConn(ctx, c, name, h1)
}
