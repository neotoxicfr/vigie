// Package config lit et valide le fichier de configuration. Aucune valeur par
// défaut ne suppose une infrastructure particulière.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/neotoxicfr/vigie/internal/ai"
)

// Config : l'amorçage (écoute, données, authentification) reste dans le fichier ;
// Runtime sert de valeurs initiales, puis vit en base et se règle dans l'interface.
type Config struct {
	Listen  string `yaml:"listen" json:"listen"`
	DataDir string `yaml:"data_dir" json:"data_dir"`
	Auth    Auth   `yaml:"auth" json:"auth"`
	Runtime `yaml:",inline"`
}

// Runtime : tout ce qui se règle dans l'interface.
type Runtime struct {
	// IP publiques de sortie de la machine, si on les connaît : sert à marquer
	// un point de vue comme privilégié. vigie n'interroge aucun service tiers.
	PublicIPs  []netip.Addr `yaml:"public_ips" json:"public_ips"`
	Sources    Sources      `yaml:"sources" json:"sources"`
	Vantages   Vantages     `yaml:"vantages" json:"vantages"`
	Policy     Policy       `yaml:"policy" json:"policy"`
	Scan       Scan         `yaml:"scan" json:"scan"`
	AI         ai.Config    `yaml:"ai" json:"ai"`
	MCP        MCP          `yaml:"mcp" json:"mcp"`
	API        API          `yaml:"api" json:"api"`
	CDN        CDN          `yaml:"cdn" json:"cdn"`
	Exclusions []string     `yaml:"exclusions" json:"exclusions"` // contrôles assumés partout : plus enregistrés
}

// Chemins par défaut des secrets : ceux des Docker secrets.
const (
	SecretAnthropic  = "/run/secrets/anthropic_api_key"
	SecretCloudflare = "/run/secrets/cloudflare_api_token"
	SecretMCP        = "/run/secrets/mcp_token"
	SecretSummary    = "/run/secrets/summary_token"
	DefaultResolver  = "1.1.1.1:53"
)

var (
	proxyName       = regexp.MustCompile(`^[a-z0-9-]{1,20}$`)
	reservedVantage = map[string]bool{"public": true, "dns": true, "origine": true, "interne": true, "inconnu": true, "config": true}
)

// DefaultRuntime : aucune valeur liée à une infrastructure, seulement des bornes
// et les chemins de secrets standard.
func DefaultRuntime() Runtime {
	return Runtime{
		Scan: Scan{Budget: 20000, Timeout: "2h", Resolver: DefaultResolver},
		AI:   ai.Config{APIKeyFile: SecretAnthropic},
		MCP:  MCP{TokenFile: SecretMCP},
		API:  API{TokenFile: SecretSummary},
		CDN:  CDN{Cloudflare: Cloudflare{TokenFile: SecretCloudflare}},
	}
}

// API : résumé en lecture seule sur /api/summary (compteurs, aucun nom d'hôte),
// actif seulement si le fichier contient un jeton.
type API struct {
	TokenFile string `yaml:"token_file" json:"token_file"` // jeton d'au moins 32 caractères
}

// MCP : serveur MCP sur /mcp, actif seulement si le fichier contient un jeton.
type MCP struct {
	TokenFile string `yaml:"token_file" json:"token_file"` // jeton d'au moins 32 caractères
}

type CDN struct {
	Cloudflare Cloudflare `yaml:"cloudflare" json:"cloudflare"`
}

// Cloudflare : jeton API restreint en lecture (Zone, DNS, Zone Settings, Firewall Services).
type Cloudflare struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	TokenFile string `yaml:"token_file" json:"token_file"`
}

type Sources struct {
	Traefik []Traefik `yaml:"traefik" json:"traefik"`
	Caddy   []Named   `yaml:"caddy" json:"caddy"` // Location = URL de l'API admin
	Nginx   []Named   `yaml:"nginx" json:"nginx"` // Location = dossier contenant nginx.conf (lecture seule)
	NPM     []Named   `yaml:"npm" json:"npm"`     // Location = base SQLite de Nginx Proxy Manager (lecture seule)
}

type Named struct {
	Name     string `yaml:"name" json:"name"`
	Location string `yaml:"location" json:"location"`
}

// ExitProxy : sortie par un proxy (VPN, autre site…) pour mesurer depuis l'extérieur.
type ExitProxy struct {
	Name         string `yaml:"name" json:"name"`                   // nom du point de vue, ex. « vpn », « bureau »
	URL          string `yaml:"url" json:"url"`                     // http://hôte:port ou socks5://hôte:port
	Username     string `yaml:"username" json:"username"`           // optionnel
	PasswordFile string `yaml:"password_file" json:"password_file"` // secret, ex. /run/secrets/vpn_proxy_password
}

// Vantages : points de vue mesurés en plus de la résolution DNS normale.
type Vantages struct {
	Proxies  []ExitProxy  `yaml:"proxies" json:"proxies"`
	Internal []netip.Addr `yaml:"internal" json:"internal"` // adresse du reverse proxy jointe directement
}

type Policy struct {
	Public         []string            `yaml:"public" json:"public"`                   // hôtes publics voulus (motifs path.Match)
	Templates      map[string][]string `yaml:"templates" json:"templates"`             // modèle → middlewares attendus
	RouteTemplates map[string]string   `yaml:"route_templates" json:"route_templates"` // motif de nom de route → modèle
	AutheliaConfig string              `yaml:"authelia_config" json:"authelia_config"` // configuration.yml, seul access_control est lu
}

type Scan struct {
	Budget   int    `yaml:"budget" json:"budget"`     // opérations réseau max par passage
	Ports    []int  `yaml:"ports" json:"ports"`       // ports TCP explorés ; vide = liste par défaut
	Resolver string `yaml:"resolver" json:"resolver"` // ip:port ; vide = /etc/resolv.conf
	Timeout  string `yaml:"timeout" json:"timeout"`   // durée max d'un passage, ex. "2h"
	// Pages : hôte → page à juger à la place de « / » (racine qui n'est pas une page,
	// ex. un « OK » en texte) ; chemin absolu, requête permise.
	Pages map[string]string `yaml:"pages" json:"pages"`
}

// Traefik : API d'une instance (entrypoint dédié de préférence), en lecture seule.
type Traefik struct {
	Name         string `yaml:"name" json:"name"`
	URL          string `yaml:"url" json:"url"`
	Username     string `yaml:"username" json:"username"`
	PasswordFile string `yaml:"password_file" json:"password_file"` // mot de passe dans un fichier, jamais dans la config
}

type Auth struct {
	Users []User `yaml:"users" json:"users"`
	Proxy *Proxy `yaml:"proxy" json:"proxy"`
}

type User struct {
	Name         string `yaml:"name" json:"name"`
	PasswordHash string `yaml:"password_hash" json:"password_hash"` // PHC argon2id : $argon2id$v=19$m=…,t=…,p=…$sel$hash
}

// Proxy : en-tête d'utilisateur posé par un proxy d'authentification, cru
// seulement quand la connexion vient d'une des plages déclarées.
type Proxy struct {
	Header         string         `yaml:"header" json:"header"`
	TrustedProxies []netip.Prefix `yaml:"trusted_proxies" json:"trusted_proxies"`
}

const maxSize = 1 << 20

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > maxSize {
		return nil, fmt.Errorf("%s : plus de %d octets", path, maxSize)
	}
	return Parse(b)
}

func Parse(b []byte) (*Config, error) {
	c := Config{Listen: ":8080", DataDir: "/data", Runtime: DefaultRuntime()}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("config : %w", err)
	}
	return &c, c.validate()
}

func (c *Config) validate() error {
	var errs []error
	if len(c.Auth.Users) == 0 && c.Auth.Proxy == nil {
		errs = append(errs, errors.New("auth : aucun utilisateur ni proxy d'authentification, vigie refuse de démarrer sans auth"))
	}
	seen := map[string]bool{}
	for i, u := range c.Auth.Users {
		switch {
		case u.Name == "":
			errs = append(errs, fmt.Errorf("auth.users[%d] : nom vide", i))
		case seen[u.Name]:
			errs = append(errs, fmt.Errorf("auth.users[%d] : %q en double", i, u.Name))
		}
		seen[u.Name] = true
		if !strings.HasPrefix(u.PasswordHash, "$argon2id$") {
			errs = append(errs, fmt.Errorf("auth.users[%d] : password_hash doit être un hash argon2id (vigie hash-password)", i))
		}
	}
	if p := c.Auth.Proxy; p != nil {
		if p.Header == "" {
			errs = append(errs, errors.New("auth.proxy.header vide"))
		}
		if len(p.TrustedProxies) == 0 {
			errs = append(errs, errors.New("auth.proxy.trusted_proxies vide : l'en-tête serait cru de n'importe qui"))
		}
	}
	if err := c.Runtime.Validate(); err != nil {
		errs = append(errs, err)
	}
	if c.Listen == "" || c.DataDir == "" {
		errs = append(errs, errors.New("listen et data_dir ne peuvent pas être vides"))
	}
	return errors.Join(errs...)
}

// Validate vérifie les réglages, au chargement comme à chaque enregistrement
// depuis l'interface.
func (c *Runtime) Validate() error {
	var errs []error
	names := map[string]bool{}
	for i, t := range c.Sources.Traefik {
		switch {
		case t.Name == "":
			errs = append(errs, fmt.Errorf("sources.traefik[%d] : nom vide", i))
		case names[t.Name]:
			errs = append(errs, fmt.Errorf("sources.traefik[%d] : %q en double", i, t.Name))
		}
		names[t.Name] = true
		if u, err := url.Parse(t.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			errs = append(errs, fmt.Errorf("sources.traefik[%d] : url http(s) sans identifiants attendue", i))
		}
		if (t.Username == "") != (t.PasswordFile == "") {
			errs = append(errs, fmt.Errorf("sources.traefik[%d] : username et password_file vont ensemble", i))
		}
	}
	for kind, list := range map[string][]Named{"caddy": c.Sources.Caddy, "nginx": c.Sources.Nginx, "npm": c.Sources.NPM} {
		seen := map[string]bool{}
		for i, n := range list {
			if n.Name == "" || n.Location == "" || seen[n.Name] {
				errs = append(errs, fmt.Errorf("sources.%s[%d] : name unique et location requis", kind, i))
			}
			seen[n.Name] = true
		}
	}
	for i, u := range c.Sources.Caddy {
		if p, err := url.Parse(u.Location); err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
			errs = append(errs, fmt.Errorf("sources.caddy[%d] : location doit être l'URL http(s) de l'API admin", i))
		}
	}
	for i, p := range c.Scan.Ports {
		if p < 1 || p > 65535 {
			errs = append(errs, fmt.Errorf("scan.ports[%d] : %d hors de 1-65535", i, p))
		}
	}
	for h, pg := range c.Scan.Pages {
		if u, err := url.Parse(pg); h == "" || err != nil || !strings.HasPrefix(pg, "/") || strings.HasPrefix(pg, "//") || u.Host != "" {
			errs = append(errs, fmt.Errorf("scan.pages[%q] : chemin absolu attendu, ex. /app/index.html", h))
		}
	}
	if c.Scan.Budget < 1 {
		errs = append(errs, errors.New("scan.budget doit être positif"))
	}
	if d, err := time.ParseDuration(c.Scan.Timeout); err != nil || d <= 0 {
		errs = append(errs, errors.New("scan.timeout : durée invalide, ex. \"2h\""))
	}
	for pat := range c.Policy.RouteTemplates {
		if _, ok := c.Policy.Templates[c.Policy.RouteTemplates[pat]]; !ok {
			errs = append(errs, fmt.Errorf("policy.route_templates[%q] : modèle inconnu", pat))
		}
	}
	if err := c.AI.Validate(); err != nil {
		errs = append(errs, err)
	}
	pnames := map[string]bool{}
	for i, p := range c.Vantages.Proxies {
		if !proxyName.MatchString(p.Name) || reservedVantage[p.Name] || pnames[p.Name] {
			errs = append(errs, fmt.Errorf("vantages.proxies[%d] : nom unique de 1 à 20 caractères [a-z0-9-], autre que public, dns, origine, interne, inconnu, config", i))
		}
		pnames[p.Name] = true
		u, err := url.Parse(p.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "socks5" && u.Scheme != "socks5h") || u.Host == "" || u.User != nil {
			errs = append(errs, fmt.Errorf("vantages.proxies[%d] : url http:// ou socks5:// sans identifiants attendue", i))
		}
		if p.Username != "" && p.PasswordFile == "" {
			errs = append(errs, fmt.Errorf("vantages.proxies[%d] : password_file requis avec username", i))
		}
	}
	if c.CDN.Cloudflare.Enabled && c.CDN.Cloudflare.TokenFile == "" {
		errs = append(errs, errors.New("cdn.cloudflare.token_file requis quand Cloudflare est activé"))
	}
	if c.Scan.Resolver != "" {
		if _, err := netip.ParseAddrPort(c.Scan.Resolver); err != nil {
			errs = append(errs, errors.New("scan.resolver : ip:port attendu, ex. 1.1.1.1:53"))
		}
	}
	for i, x := range c.Exclusions {
		if x == "" || strings.ContainsAny(x, " \t\n") {
			errs = append(errs, fmt.Errorf("exclusions[%d] : identifiant de contrôle invalide", i))
		}
	}
	return errors.Join(errs...)
}
