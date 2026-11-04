<div align="center">

<img src="internal/web/static/icon.svg" width="72" height="72" alt="">

# vigie

**L'audit de ta configuration web exposée, vu de l'intérieur, là où les scanners en ligne butent sur le mur.**

[![CI](https://github.com/neotoxicfr/vigie/actions/workflows/ci.yml/badge.svg)](https://github.com/neotoxicfr/vigie/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/neotoxicfr/vigie?sort=semver)](https://github.com/neotoxicfr/vigie/releases)
[![Licence : MIT ou Apache-2.0](https://img.shields.io/badge/licence-MIT%20%2F%20Apache--2.0-blue)](#licence)
[![Image](https://img.shields.io/badge/ghcr.io-neotoxicfr%2Fvigie-2496ED?logo=docker&logoColor=white)](https://github.com/neotoxicfr/vigie/pkgs/container/vigie)

</div>

---

Les scanners en ligne (Mozilla HTTP Observatory, SSL Labs…) testent depuis l'étranger ou depuis des hébergeurs. Ils
butent sur le géoblocage, l'IPS ou le portail d'authentification : **ils testent le mur, pas le site.**

vigie tourne chez toi. Il lit la configuration de ton reverse proxy pour connaître tous tes services, les mesure
depuis plusieurs points de vue et **déduit** ce qu'un inconnu verrait. Chaque passage est comparé au précédent : les
écarts nouveaux passent devant, ceux que tu assumes (avec une raison) se rangent.

**Pour qui ?** Les administrateurs qui auto-hébergent leurs services derrière Traefik, Caddy, nginx ou Nginx Proxy
Manager (homelab, petite infra), seuls ou à plusieurs : chaque écart assumé garde son auteur, sa date et sa raison.

## Sommaire

- [Ce que fait vigie](#ce-que-fait-vigie)
- [Démarrage rapide](#démarrage-rapide)
- [Configuration](#configuration)
- [IA et MCP](#ia-et-mcp)
- [Sécurité](#sécurité)
- [Architecture](#architecture)
- [Limites](#limites)
- [Développement](#développement)
- [Licence](#licence)

## Ce que fait vigie

| | |
|---|---|
| **Découverte** | API de Traefik (v2/v3), API admin de Caddy, fichiers nginx, base de Nginx Proxy Manager, cibles saisies à la main. Tout en lecture seule. |
| **Points de vue mesurés** | `dns` (résolution normale, donc le CDN s'il y en a un) ; `origine` (adresses lues dans les enregistrements proxifiés Cloudflare, testées en contournant le CDN) ; `interne` (le reverse proxy joint directement) ; sorties par proxy HTTP CONNECT ou SOCKS5 (ce que voit un visiteur extérieur). |
| **Vue `inconnu`** | Déduite des allowlists, des forward-auth, du basic-auth, des règles Authelia (si tu fournis le fichier) et du pare-feu Cloudflare. Jamais mesurée, et présentée comme telle. |
| **Points de vue privilégiés** | Quand la machine de vigie passe une allowlist ou un bypass qu'un inconnu ne passerait pas, chaque constat le dit. |
| **HTTP** | En-têtes de sécurité, CSP, cookies, CORS, méthodes, redirections, versions annoncées, pages d'erreur bavardes, SRI, contenu mixte, fuites de fichiers, technos détectées (Wappalyzer), HTTP/2, HTTP/3, WebSocket et SSE. |
| **TLS** | SSLv3 à TLS 1.3 avec énumération des suites, chaîne et lint des certificats (zlint), certificat par défaut. |
| **DNS et courrier** | DNSSEC validé jusqu'à la racine, CAA, SPF, DMARC, MTA-STS, TLS-RPT, origine exposée par le DNS. |
| **Réseau** | Ports courants (35 par défaut), algorithmes SSH, parité IPv4/IPv6. |
| **Proxy** | Chaîne de middlewares attendue par route, comparée à la chaîne réelle. |
| **Tri** | Chaque écart est nouveau, toujours là ou résolu ; on l'assume pour un hôte ou partout, avec une raison, et on revient dessus dans les réglages. |
| **Sorties** | Interface web et export JSON de chaque passage. **Rien ne sort de l'instance** sauf l'analyse IA, à ta demande. |

Tous les contrôles sont natifs, en Go, sans outil externe (ni testssl, ni nuclei, ni ZAP).

**Garde-fous** : vigie reste passif et léger. Au plus 2 connexions simultanées par hôte, 250 ms entre deux départs
vers le même hôte, 20 départs par seconde au total, un budget d'opérations par passage ; un hôte qui répond 429 est
suspendu jusqu'à la fin du passage. Jamais d'essai d'identifiants, de POST métier ni de fuzzing.

## Démarrage rapide

L'image est multi-architecture (`linux/amd64`, `linux/arm64`), distroless, et tourne en utilisateur non root
(uid 65532).

**1. Préparer le dossier et un mot de passe**

```sh
mkdir -p vigie/data && cd vigie
sudo chown 65532:65532 data
docker run --rm -i ghcr.io/neotoxicfr/vigie:0.5.0 hash-password   # 12 caractères au moins
```

**2. Écrire `config.yaml`** (exemple complet et commenté : [`config.example.yaml`](config.example.yaml))

```yaml
auth:
  users:
    - name: admin
      password_hash: "$argon2id$v=19$m=65536,t=3,p=2$..."   # sortie de hash-password
sources:
  traefik:
    - name: principal
      url: http://traefik:8080      # API de Traefik, en lecture seule
policy:
  public: ["www.example.com"]       # hôtes publics voulus
```

**3. Lancer**

```sh
docker run -d --name vigie --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  -e TZ=Europe/Paris -p 8080:8080 \
  -v "$PWD/config.yaml:/config/config.yaml:ro" -v "$PWD/data:/data" \
  ghcr.io/neotoxicfr/vigie:0.5.0
```

Ou avec Compose, à partir de [`compose.example.yml`](compose.example.yml) :

```yaml
services:
  vigie:
    image: ghcr.io/neotoxicfr/vigie:0.5.0
    restart: unless-stopped
    read_only: true
    security_opt: ["no-new-privileges:true"]
    cap_drop: [ALL]
    environment:
      - TZ=Europe/Paris
    volumes:
      - ./config.yaml:/config/config.yaml:ro
      - ./data:/data
      # - ./secrets:/run/secrets:ro   # clés d'API, jetons, mots de passe
    networks: [proxy]                 # le réseau où l'API du reverse proxy est joignable
networks:
  proxy:
    external: true
```

Ouvre `http://<hôte>:8080`, connecte-toi, puis **Lancer un passage**. La cadence des passages planifiés se règle dans
**Réglages**.

Tags de l'image : `X.Y.Z` (sans « v »), `X.Y` et `latest`.

### Commandes

| Commande | Rôle |
|---|---|
| `vigie serve` | Interface web et passages planifiés (défaut). |
| `vigie scan` | Un passage complet, puis sortie (code 1 en cas d'échec). |
| `vigie discover` | Inventaire JSON des routes de toutes les sources. |
| `vigie hash-password` | Lit un mot de passe sur l'entrée standard et écrit son hash argon2id. |
| `vigie healthcheck` | Vérifie que l'interface répond (sonde `HEALTHCHECK` de l'image). |
| `vigie version` | Affiche la version. |

Option commune : `-config <fichier>` (défaut `/config/config.yaml`, ou la variable `VIGIE_CONFIG`).

## Configuration

`config.yaml` contient **l'amorçage** (écoute, données, authentification). Tout le reste **n'initialise** les
réglages qu'au premier démarrage : ils vivent ensuite en base et se modifient dans **Réglages**, sans redémarrage.
Aucune valeur par défaut ne suppose une infrastructure particulière.

### Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `VIGIE_CONFIG` | `/config/config.yaml` | Chemin du fichier de configuration. |
| `TZ` | UTC | Fuseau des heures affichées (base de fuseaux embarquée dans le binaire). |

### Amorçage (fichier seulement)

| Clé | Défaut | Rôle |
|---|---|---|
| `listen` | `:8080` | Adresse d'écoute de l'interface. |
| `data_dir` | `/data` | Dossier de la base SQLite `vigie.db`. |
| `auth.users[]` | — | `name` et `password_hash` (argon2id, `vigie hash-password`). |
| `auth.proxy.header` | — | En-tête d'utilisateur posé par un proxy d'authentification (ex. `Remote-User`). |
| `auth.proxy.trusted_proxies` | — | Plages CIDR d'où cet en-tête est cru ; obligatoire avec `header`. |

Il faut au moins un utilisateur ou un proxy d'authentification : **sans authentification, vigie refuse de démarrer.**

### Réglages (fichier au premier démarrage, puis interface)

| Clé | Défaut | Rôle |
|---|---|---|
| `public_ips` | `[]` | Tes IP publiques de sortie, pour marquer les mesures privilégiées. vigie n'interroge aucun service tiers pour les deviner. |
| `sources.traefik[]` | `[]` | `name`, `url` de l'API, et si elle est protégée `username` + `password_file`. |
| `sources.caddy[]` | `[]` | `name`, `location` : URL de l'API admin (ex. `http://caddy:2019`). |
| `sources.nginx[]` | `[]` | `name`, `location` : dossier contenant `nginx.conf`, monté en lecture seule. |
| `sources.npm[]` | `[]` | `name`, `location` : base SQLite de Nginx Proxy Manager, en lecture seule. |
| `vantages.internal` | `[]` | Adresses du reverse proxy jointes directement (point de vue `interne`). |
| `vantages.proxies[]` | `[]` | Sorties par proxy : `name` (`[a-z0-9-]`, 20 caractères au plus), `url` (`http://` ou `socks5://`), `username` et `password_file` optionnels. |
| `policy.public` | `[]` | Hôtes publics voulus (motifs `path.Match`, ex. `*.pub.example.com`). Un hôte exposé sans contrôle d'accès hors de cette liste est un écart élevé. |
| `policy.templates` | `{}` | Modèles de chaîne de middlewares, ex. `{admin: [crowdsec, ratelimit, authelia]}`. |
| `policy.route_templates` | `{}` | Motif de nom de route → modèle attendu, ex. `{"*@docker": admin}`. |
| `policy.authelia_config` | `""` | `configuration.yml` d'Authelia ; seul `access_control` est lu. |
| `scan.budget` | `20000` | Opérations réseau au plus par passage. |
| `scan.ports` | `[]` | Ports TCP explorés ; vide = 35 ports courants. |
| `scan.resolver` | `1.1.1.1:53` | Résolveur `ip:port` ; chaîne vide = premier serveur de `/etc/resolv.conf`. |
| `scan.timeout` | `2h` | Durée maximale d'un passage. |
| `scan.pages` | `{}` | Hôte → page à juger à la place de `/` quand la racine n'est pas une vraie page, ex. `office.example.com: /browser/dist/cool.html`. |
| `cdn.cloudflare.enabled` | `false` | Lit les zones Cloudflare (enregistrements proxifiés, réglages, pare-feu) pour le point de vue `origine` et la vue `inconnu`. |
| `cdn.cloudflare.token_file` | `/run/secrets/cloudflare_api_token` | Jeton restreint en lecture : Zone Read, Zone Settings Read, SSL and Certificates Read, DNS Read, Zone WAF Read. La Global API Key est refusée. |
| `ai.provider` | `""` | `anthropic` ou `openai` (toute API compatible). Vide = analyse désactivée. |
| `ai.model` | `claude-opus-5-5` pour `anthropic` | Modèle utilisé. |
| `ai.base_url` | `""` | Pour `openai` : ex. `http://ollama:11434/v1`. |
| `ai.api_key_file` | `/run/secrets/anthropic_api_key` | Clé d'API dans un fichier. |
| `ai.context` | `""` | Choix déjà tranchés, donnés à chaque analyse (8 000 caractères au plus). |
| `mcp.token_file` | `/run/secrets/mcp_token` | Jeton du serveur MCP (32 caractères au moins) ; `/mcp` n'existe pas sans lui. |
| `api.token_file` | `/run/secrets/summary_token` | Jeton de `GET /api/summary` (32 caractères au moins). |
| `exclusions` | `[]` | Contrôles assumés partout : plus enregistrés. Se gère dans Réglages > Exclusions. |

Les secrets ne sont jamais dans la configuration : seulement des chemins de fichiers, pensés pour les
[Docker secrets](https://docs.docker.com/compose/how-tos/use-secrets/) (`/run/secrets/<nom>`). Un jeton se génère
avec `openssl rand -hex 32`.

### Points d'accès pour l'outillage

- `GET /healthz` : répond `ok`, sans authentification.
- `GET /api/summary` : résumé en lecture seule pour un tableau de bord (compteurs, dernier passage, notes, **aucun nom
  d'hôte**), avec l'en-tête `Authorization: Bearer <jeton>`.
- `GET /runs/<passage>/export.json` : export complet d'un passage (session requise).

## IA et MCP

**Analyse d'un passage** (bouton sur la page du passage, jamais automatique) :

- Anthropic, ou toute API compatible OpenAI (Ollama, LM Studio, OpenRouter…), donc une IA locale si tu ne veux rien
  faire sortir ;
- envoi des constats et des chaînes de middlewares, jamais de la configuration brute ni d'un secret ;
- la case **masquer** remplace noms d'hôtes et IP par des jetons avant l'envoi, puis les rétablit dans la réponse.

**Serveur MCP** sur `/mcp` (HTTP streamable, jeton porteur) :

- outils `vigie_list_runs`, `vigie_findings`, `vigie_inventory`, `vigie_analysis` (lecture) et `vigie_start_run` ;
- aucune écriture sur le tri : assumer un écart reste un geste humain ;
- derrière un portail d'authentification, exclure `/mcp` du forward-auth (règle de bypass ou route dédiée) : c'est
  le jeton porteur qui protège ce chemin.

```sh
claude mcp add --transport http vigie https://vigie.example.com/mcp \
  --header "Authorization: Bearer $(cat mcp.token)"
```

## Sécurité

- **Authentification obligatoire** : comptes locaux (argon2id, sessions de 12 h révoquées à la déconnexion, verrouillage
  de 15 min après 5 échecs par IP et utilisateur ou 20 par IP), ou en-tête d'un proxy d'authentification cru
  **seulement** depuis `trusted_proxies`.
- **Derrière Authelia ou Authentik** : vigie croit l'en-tête de *toute* requête venue de ces plages. La route de vigie
  doit passer par le forward-auth, qui réécrit l'en-tête, et aucune autre route ne doit pouvoir joindre vigie.
- **Interface durcie** : CSP stricte (`default-src 'none'`, aucun script ni style en ligne), `frame-ancestors 'none'`,
  `nosniff`, `no-referrer`, jeton CSRF sur chaque formulaire, cookies `HttpOnly` et `SameSite=Lax`.
- **Lecture seule** sur les sources ; aucune donnée envoyée ailleurs sans action explicite.
- **Image** : distroless sans shell, utilisateur non root, compatible `read_only` et `cap_drop: [ALL]`. Chaque image
  publiée porte une attestation de provenance signée :

  ```sh
  gh attestation verify oci://ghcr.io/neotoxicfr/vigie:0.5.0 -R neotoxicfr/vigie
  ```

Signaler une vulnérabilité : voir [SECURITY.md](SECURITY.md).

## Architecture

Un binaire Go statique, une base SQLite (pur Go, sans CGO), une interface rendue côté serveur (`html/template`) avec
un peu de JavaScript en amélioration progressive.

```
sources (Traefik, Caddy, nginx, NPM, manuel)
        │  routes, middlewares, allowlists
        ▼
policy ── vue « inconnu » déduite (authprov/authelia, cdnprov/cloudflare)
        │
engine ── points de vue (dns, origine, interne, sorties proxy) sous garde-fous (scan)
        │  probe (HTTP), tlsscan, dnsscan, portscan
        ▼
store (SQLite) ── comparaison au passage précédent, tri, exclusions
        │
        ├── web : interface, export JSON, /api/summary
        ├── mcpserver : /mcp
        └── ai : analyse à la demande
```

| Paquet | Rôle |
|---|---|
| `cmd/vigie` | Point d'entrée et sous-commandes. |
| `internal/source/*` | Lecture des routes de chaque reverse proxy. |
| `internal/policy`, `internal/authprov`, `internal/cdnprov` | Chaîne attendue, vue `inconnu`, règles du CDN. |
| `internal/engine`, `internal/scan` | Orchestration d'un passage, points de vue, garde-fous. |
| `internal/probe`, `internal/tlsscan`, `internal/dnsscan`, `internal/portscan` | Contrôles. |
| `internal/kb` | Base de connaissances : explication et correctifs par proxy pour chaque contrôle. |
| `internal/netinfo` | IP de sortie, plages CDN embarquées. |
| `internal/store`, `internal/settings`, `internal/sched` | Base, réglages vivants, passages planifiés. |
| `internal/web`, `internal/mcpserver`, `internal/ai` | Interface, MCP, analyse IA. |

## Limites

- Pas de vraie vue externe sans sortie par proxy : les mesures partent de la machine de vigie, et la vue d'un inconnu
  est déduite.
- Hors Cloudflare, les règles du CDN (géoblocage, WAF) ne sont pas lues.
- Ports vus depuis le réseau local : marqués « non représentatif de l'extérieur ».
- Ni DKIM (il faudrait connaître les sélecteurs), ni services UDP silencieux comme WireGuard.

## Développement

Prérequis : Go (version de `go.mod`). `govulncheck` : `go install golang.org/x/vuln/cmd/govulncheck@latest`.

```sh
go run ./cmd/vigie -config config.yaml serve   # data_dir doit être inscriptible
scripts/ci.sh                                   # gofmt, vet, tests -race, govulncheck, build statique
docker buildx build --platform linux/amd64,linux/arm64 .
```

La CI GitHub Actions lance les mêmes contrôles sur chaque push et pull request. Un tag `vX.Y.Z` publie l'image
`ghcr.io/neotoxicfr/vigie:X.Y.Z` et crée la release.

Les contributions sont bienvenues : ouvre d'abord une issue pour un changement important, et garde les exemples
génériques (`example.com`, IP de documentation).

## Licence

Au choix, sous l'une ou l'autre de ces licences :

- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT ([LICENSE-MIT](LICENSE-MIT))

Sauf mention contraire, toute contribution proposée est publiée sous ces deux mêmes licences.
