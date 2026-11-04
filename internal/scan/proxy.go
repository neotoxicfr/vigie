package scan

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
)

// Proxy : sortie par un proxy HTTP (CONNECT) ou SOCKS5. Les connexions TCP
// partent de l'adresse du proxy ; le nom est résolu par lui, comme pour un
// visiteur de cette sortie. Pas d'UDP : HTTP/3 n'y passe pas.
type Proxy struct {
	URL      *url.URL // http://hôte:port ou socks5://hôte:port, identifiant éventuel dans URL.User
	Password string   // lu dans un fichier secret, jamais dans l'URL enregistrée
}

// ProxyVantage : point de vue « sortie par proxy ».
func ProxyVantage(name string, p *Proxy) Vantage {
	return Vantage{Name: name, Proxy: p, Addrs: func(context.Context, string) ([]netip.Addr, error) { return nil, nil }}
}

func (p *Proxy) user() string {
	if p.URL.User == nil {
		return ""
	}
	return p.URL.User.Username()
}

// Dial ouvre host:port à travers le proxy.
func (p *Proxy) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	d := &net.Dialer{Timeout: 10 * time.Second}
	switch p.URL.Scheme {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u := p.user(); u != "" {
			auth = &proxy.Auth{User: u, Password: p.Password}
		}
		sd, err := proxy.SOCKS5("tcp", p.URL.Host, auth, d)
		if err != nil {
			return nil, err
		}
		cd, ok := sd.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("proxy SOCKS5 sans contexte")
		}
		c, err := cd.DialContext(ctx, "tcp", target)
		if err != nil {
			return nil, fmt.Errorf("proxy %s : %w", p.URL.Host, err)
		}
		return c, nil
	case "http":
		c, err := d.DialContext(ctx, "tcp", p.URL.Host)
		if err != nil {
			return nil, fmt.Errorf("proxy %s : %w", p.URL.Host, err)
		}
		if dl, ok := ctx.Deadline(); ok {
			c.SetDeadline(dl)
		} else {
			c.SetDeadline(time.Now().Add(15 * time.Second))
		}
		req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
		if u := p.user(); u != "" {
			req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p.Password)) + "\r\n"
		}
		if _, err := c.Write([]byte(req + "\r\n")); err != nil {
			c.Close()
			return nil, err
		}
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("proxy %s : %w", p.URL.Host, err)
		}
		// Pas de resp.Body.Close() : certains proxys (gluetun) annoncent un corps
		// « chunked » sur le 200 ; le vider avalerait le début du tunnel.
		if resp.StatusCode != http.StatusOK {
			c.Close()
			return nil, fmt.Errorf("proxy %s : CONNECT %s refusé (%s)", p.URL.Host, target, resp.Status)
		}
		c.SetDeadline(time.Time{})
		if br.Buffered() > 0 { // octets déjà lus après la réponse : ils appartiennent au tunnel
			return &bufConn{Conn: c, r: br}, nil
		}
		return c, nil
	}
	return nil, fmt.Errorf("proxy : schéma %q non pris en charge (http ou socks5)", p.URL.Scheme)
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
