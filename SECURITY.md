# Sécurité

## Versions suivies

Seule la dernière version publiée reçoit des correctifs de sécurité. Mets à jour l'image
(`ghcr.io/neotoxicfr/vigie`) avant de signaler un problème.

## Signaler une vulnérabilité

Ne publie pas de vulnérabilité dans une issue. Utilise le signalement privé de GitHub :
onglet **Security**, puis **Report a vulnerability**
([lien direct](https://github.com/neotoxicfr/vigie/security/advisories/new)).

Indique la version, la configuration utile (sans secret ni nom d'hôte réel), les étapes pour reproduire et l'impact
estimé. Tu reçois une première réponse sous quelques jours ; le correctif et l'avis de sécurité sont publiés
ensemble, avec ton nom si tu le souhaites.

## Périmètre

Sont concernés : le binaire et l'image de vigie, son interface web, son API (`/api/summary`) et son serveur MCP
(`/mcp`). Les constats que vigie produit sur tes propres services ne sont pas des vulnérabilités de vigie.
