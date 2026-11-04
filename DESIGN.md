# Design

Registre : outil pro dense (barre GitHub, Linear, Grafana récent), mode Operate. La tâche prime sur l'expression ;
l'identité tient dans la précision des détails.

## Thème
- **Couleurs** : sombre par défaut (`data-theme="dark"`), clair au choix, gardé dans `localStorage`. Les jetons sont
  dans `internal/web/static/app.css` (`:root`, `:root[data-theme="light"]`).
- **Neutres** froids : fond `--bg`, surfaces `--surface` / `--raised` / `--hover`, filets `--line` / `--line-strong`.
- **Accent** : `--accent`, seulement pour l'action principale, l'élément courant et l'avancement.
- **Sévérités** : `--sev3` élevé (rouge), `--sev2` moyen (ambre), `--sev1` faible (bleu), `--sev0` info (gris). Toujours
  un libellé à côté de la couleur.
- **Points de vue** : `--v-public` cyan, `--v-dns` vert d'eau, `--v-origine` violet, `--v-interne` ardoise,
  `--v-inconnu` rose, `--v-config` gris. Teintes distinctes des sévérités.
- **Notes A-F** : du vert au rouge, texte sombre sur pastille pleine.

## Typographie
- Pile système pour l'interface ; monospace (`--mono`) seulement pour les hôtes, les identifiants de contrôle, le code et
  les preuves.
- Corps à 14 px, titres à 18-19 px en graisse 650.
- En-têtes de tableau en petites capitales espacées.

## Composants
- **Barre latérale** : 224 px, icônes SVG maison (un seul trait de 1,8). Sur mobile, elle devient une barre d'icônes en
  haut.
- **Barre du haut** : titre de page, dernier passage ou avancement en direct, bouton « Lancer un passage ».
- **Tableau des écarts** : une ligne par écart (contrôle et cible) avec la pastille de sévérité, le titre et
  l'identifiant, la cible, les pastilles de points de vue et l'état. Sur mobile, chaque ligne devient une carte.
- **Pastilles de points de vue** :
  - pleines si le point de vue voit l'écart ;
  - pointillées et barrées si c'est résolu ;
  - un point ambre si la mesure est privilégiée.
- **Tiroir latéral** (720 px) pour le détail d'un écart, chargé sans rechargement de page. Sans JS, on obtient la page
  complète `/issue/{clé}`.
- **Filtres** : sévérités et points de vue en cases à cocher en forme de pastilles, appliqués à la volée, et onglets
  d'état avec leurs compteurs.
- **Correctifs** : un onglet par proxy, le bloc de code avec un bouton de copie.
- **Assumer** : une portée « cet hôte » ou « partout », qui exclut le contrôle des passages. On défait une exclusion
  dans Réglages > Exclusions.

## Règles
- CSP stricte : aucun style ni script en ligne. Le JS (`static/app.js`) n'est qu'une amélioration progressive.
- Cibles tactiles de 34 px au moins sur bureau et de 40 px sur mobile. Focus visible partout.
- Le mouvement se limite aux changements d'état (tiroir, avancement), sur `transform` ou `opacity`, et il est coupé si
  l'utilisateur demande moins d'animations (`prefers-reduced-motion`).
- Les passages sont identifiés par leur date (« 23 oct. 09:31 »), jamais par un numéro.
