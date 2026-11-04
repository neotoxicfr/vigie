package scan

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeProxy : proxy HTTP CONNECT minimal qui exige user:pass et relaie vers backend.
func fakeProxy(t *testing.T, backend string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				if req.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("vigie:s3cret")) {
					io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
					return
				}
				b, err := net.Dial("tcp", backend)
				if err != nil {
					io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer b.Close()
				// Comme gluetun : un en-tête de corps sur la réponse au CONNECT, à ignorer.
				io.WriteString(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
				go io.Copy(b, c)
				io.Copy(c, b)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestProxyConnect(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	addr := fakeProxy(t, echo.Addr().String())
	u, _ := url.Parse("http://" + addr)
	u.User = url.User("vigie")
	g := NewGuard(100, 2, 0)
	v := ProxyVantage("vpn", &Proxy{URL: u, Password: "s3cret"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := g.Dial(ctx, v, "app.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "bonjour\n")
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if line != "bonjour\n" {
		t.Errorf("tunnel : %q", line)
	}
	bad := ProxyVantage("vpn", &Proxy{URL: u, Password: "faux"})
	if _, err := g.Dial(ctx, bad, "app.example.com", 443); err == nil || !strings.Contains(err.Error(), "407") {
		t.Errorf("mauvais mot de passe : %v", err)
	}
	ftp, _ := url.Parse("ftp://" + addr)
	if _, err := (&Proxy{URL: ftp}).Dial(ctx, "x", 1); err == nil {
		t.Error("schéma inconnu accepté")
	}
}
