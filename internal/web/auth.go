package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/neotoxicfr/vigie/internal/config"
	"github.com/neotoxicfr/vigie/internal/store"
)

// Paramètres argon2id : au-dessus du minimum OWASP (m=19 Mio, t=2, p=1).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

// HashPassword rend un hash PHC argon2id, à coller dans auth.users[].password_hash.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

func verifyPassword(phc, pw string) bool {
	parts := strings.Split(phc, "$") // "", argon2id, v=19, m=…,t=…,p=…, sel, hash
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 || m > 1<<22 {
		return false
	}
	b64 := base64.RawStdEncoding
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash sert à passer le même temps sur un utilisateur inconnu.
var dummyHash, _ = HashPassword("vigie")

type auth struct {
	cfg config.Auth
	key []byte
	st  *store.Store // génération de session par utilisateur (déconnexion = révocation)

	mu    sync.Mutex
	fails map[string]*failState // clés « ip » et « ip|utilisateur »
}

// argonSem borne les vérifications argon2 simultanées (64 Mio chacune) : une
// rafale de connexions ne peut pas épuiser la mémoire.
var argonSem = make(chan struct{}, 2)

type failState struct {
	n           int
	last, until time.Time
}

const (
	sessionCookie = "vigie_session"
	sessionTTL    = 12 * time.Hour
	maxFails      = 5  // par couple IP + utilisateur
	maxFailsIP    = 20 // par IP, tous noms confondus
	lockout       = 15 * time.Minute
)

// loadKey lit ou crée la clé de signature des sessions (32 octets, mode 0600).
func loadKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%s : clé de %d octets, attendu 32 (supprime le fichier pour en recréer une)", path, len(b))
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return nil, err
	}
	return b, f.Close()
}

func peer(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, _ := netip.ParseAddr(host)
	return a.Unmap()
}

// clientIP : derrière un proxy déclaré, la dernière adresse de X-Forwarded-For
// qui n'est pas un proxy de confiance ; sinon le pair TCP.
func (a *auth) clientIP(r *http.Request) netip.Addr {
	ip := peer(r)
	if !a.fromProxy(r) {
		return ip
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		c, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		c = c.Unmap()
		trusted := false
		for _, p := range a.cfg.Proxy.TrustedProxies {
			trusted = trusted || p.Contains(c)
		}
		if !trusted {
			return c
		}
	}
	return ip
}

func (a *auth) fromProxy(r *http.Request) bool {
	if a.cfg.Proxy == nil {
		return false
	}
	ip := peer(r)
	for _, p := range a.cfg.Proxy.TrustedProxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// user renvoie l'utilisateur authentifié, ou "" : en-tête du proxy seulement si
// la connexion vient d'un proxy déclaré, sinon cookie de session signé.
func (a *auth) user(r *http.Request) string {
	if a.fromProxy(r) {
		if u := strings.TrimSpace(r.Header.Get(a.cfg.Proxy.Header)); u != "" {
			return u
		}
	}
	if len(a.cfg.Users) == 0 {
		return ""
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(a.sign("session|"+payload))) {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	f := strings.Split(string(raw), "|") // nom | expiration | génération
	if len(f) != 3 {
		return ""
	}
	name := f[0]
	n, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil || time.Now().Unix() > n || f[2] != a.generation(r.Context(), name) {
		return ""
	}
	for _, u := range a.cfg.Users { // un utilisateur retiré de la config perd sa session
		if u.Name == name {
			return name
		}
	}
	return ""
}

func (a *auth) sign(s string) string {
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}

// generation change à chaque déconnexion : les cookies et jetons CSRF émis avant
// deviennent invalides, même volés.
func (a *auth) generation(ctx context.Context, user string) string {
	if a.st == nil {
		return "0"
	}
	g, err := a.st.Setting(ctx, "session_gen:"+user, "0")
	if err != nil {
		return "?" // base illisible : aucune session ne correspond
	}
	return g
}

func (a *auth) revoke(ctx context.Context, user string) error {
	g, _ := strconv.ParseInt(a.generation(ctx, user), 10, 64)
	return a.st.SetSetting(ctx, "session_gen:"+user, strconv.FormatInt(g+1, 10))
}

func (a *auth) csrfToken(ctx context.Context, user string) string {
	return a.sign("csrf|" + user + "|" + a.generation(ctx, user))
}

// checkCSRF : jeton lié à l'utilisateur, et requête de même origine.
func (a *auth) checkCSRF(r *http.Request, user string) bool {
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" && s != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		if !strings.EqualFold(strings.TrimPrefix(strings.TrimPrefix(o, "https://"), "http://"), r.Host) {
			return false
		}
	}
	return hmac.Equal([]byte(r.PostFormValue("csrf")), []byte(a.csrfToken(r.Context(), user)))
}

// login vérifie un couple. L'essai est compté AVANT la vérification : des
// requêtes parallèles ne dépassent pas la limite, et un succès efface le compte.
func (a *auth) login(ip netip.Addr, name, pw string) (ok bool, locked bool) {
	kIP, kUser := ip.String(), ip.String()+"|"+strings.ToLower(name)
	now := time.Now()
	a.mu.Lock()
	if len(a.fails) > 10000 { // borne la mémoire face à une rafale d'IP
		for k, v := range a.fails {
			if now.Sub(v.last) > lockout && now.After(v.until) {
				delete(a.fails, k)
			}
		}
	}
	for _, k := range []string{kIP, kUser} {
		if f := a.fails[k]; f != nil && now.Before(f.until) {
			a.mu.Unlock()
			return false, true
		}
	}
	for k, max := range map[string]int{kIP: maxFailsIP, kUser: maxFails} {
		f := a.fails[k]
		if f == nil || now.Sub(f.last) > lockout && now.After(f.until) {
			f = &failState{}
			a.fails[k] = f
		}
		f.n++
		f.last = now
		if f.n >= max {
			f.until = now.Add(lockout)
		}
	}
	a.mu.Unlock()

	hash := dummyHash
	known := false
	for _, u := range a.cfg.Users {
		if subtle.ConstantTimeCompare([]byte(u.Name), []byte(name)) == 1 {
			hash, known = u.PasswordHash, true
		}
	}
	argonSem <- struct{}{}
	ok = verifyPassword(hash, pw) && known
	<-argonSem

	if ok {
		a.mu.Lock()
		delete(a.fails, kUser)
		if f := a.fails[kIP]; f != nil && f.n > 0 {
			f.n-- // l'essai réussi ne compte pas contre l'IP
			if now.After(f.until) || f.n < maxFailsIP {
				f.until = time.Time{}
			}
		}
		a.mu.Unlock()
	}
	return ok, false
}

func (a *auth) setSession(w http.ResponseWriter, r *http.Request, name string) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(name + "|" + strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10) +
		"|" + a.generation(r.Context(), name)))
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: payload + "." + a.sign("session|"+payload), Path: "/",
		HttpOnly: true, Secure: secure(r, a), SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds())})
}

func (a *auth) clearSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: secure(r, a),
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// secure : cookie Secure si la connexion est en TLS, directement ou d'après un proxy déclaré.
func secure(r *http.Request, a *auth) bool {
	return r.TLS != nil || a.fromProxy(r) && r.Header.Get("X-Forwarded-Proto") == "https"
}
