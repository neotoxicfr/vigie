# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
Administrateurs qui auto-hébergent leurs services derrière un reverse proxy (homelab, petite infra). Usage solo
d'abord, mais l'outil doit rester clair quand plusieurs personnes partagent une instance et se répartissent le tri :
chaque écart assumé garde son auteur, sa date et sa raison. Ils ouvrent vigie après une modification de config ou à
intervalle régulier, surtout sur ordinateur, parfois sur téléphone, pour savoir « qu'est-ce qui a changé, qu'est-ce
qui est vraiment un problème ».

## Product Purpose
Auditer de l'intérieur la configuration web exposée (en-têtes, TLS, HTTP/2-3, DNS et mail, ports, fuites, chaîne de
middlewares) là où les scanners en ligne échouent parce qu'ils butent sur le géoblocage, l'IPS ou le portail
d'authentification. Succès : à chaque passage, l'utilisateur voit en quelques secondes les écarts nouveaux et non
assumés, et peut trier le reste (assumer avec une raison) sans bruit.

## Positioning
Lit la configuration du reverse proxy (Traefik, Caddy, nginx, Nginx Proxy Manager) pour découvrir les services et
déduire ce qu'un inconnu verrait, puis mesure depuis plusieurs points de vue (dns, origine, interne) en marquant
honnêtement quand le point de vue est privilégié. Compare chaque passage au précédent et distingue choix assumés et
vrais écarts.

## Operating Context
Service auto-hébergé (conteneur), derrière le proxy d'authentification de l'utilisateur ou avec connexion intégrée.
Résultats seulement dans l'interface et l'export JSON : aucun canal sortant (mail, webhook, notification).

## Capabilities and Constraints
- Interface Go `html/template` rendue côté serveur, **sans JavaScript** ; CSP stricte (`default-src 'none'`,
  `style-src 'self'`), donc ni style ni script en ligne, ni ressource externe (pas de webfont distante).
- Pages : tableau de bord des passages, détail d'un passage (constats groupés par cible, filtres, assumer/ne plus
  assumer), inventaire (sources, cibles manuelles, routes découvertes), connexion.
- Vocabulaire : passage, constat, écart, assumé, cible, route, source, point de vue (dns, origine, interne, inconnu),
  privilégié, sévérité (info, faible, moyen, élevé), état (nouveau, toujours là / inchangé, résolu).
- Langue de l'interface : français.

## Brand Commitments
Nom « vigie » seulement ; identité visuelle déléguée.

## Evidence on Hand
Aucune capture, aucun témoignage ni chiffre d'usage : ne rien inventer.

## Product Principles
1. Le signal avant tout : ce qui est nouveau et non assumé passe devant, le reste se trie.
2. Honnêteté du point de vue : une mesure privilégiée ou déduite ne se présente jamais comme la vue d'un inconnu.
3. Rien ne sort de l'instance sans demande.
4. Passif et léger : l'outil ne doit jamais devenir une charge ou une attaque pour ce qu'il audite.

## Accessibility & Inclusion
WCAG 2.2 AA : contrastes AA en clair et en sombre, navigation clavier complète, cibles tactiles ≥ 44 px, sévérité et
état jamais portés par la couleur seule.
