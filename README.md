# TP : Sécurisation d'une image et d'un conteneur Docker

**Application :** Quiz Docker (`dockerfile-exercice2`) : application web construite avec Vite et servie par `serve` sur le port 3000.
**Rôle :** ingénieur(e) DevOps chargé(e) de l'audit de sécurité et du renforcement de l'image avant un déploiement en production.

> Les mesures (tailles, CVE, politiques) proviennent de `docker image ls` et de `docker scout quickview` ; les sorties brutes sont dans le dossier [`resultats/`](resultats/).

---

## Contenu du dépôt

| Fichier | Rôle |
|---|---|
| `Dockerfile` | Dockerfile **initial** (avant sécurisation) → image `quiz-docker:initial` |
| `Dockerfile.secure` | Dockerfile **sécurisé** (multi-étapes, non-root) → image `quiz-docker:secure` |
| `Dockerfile.dhi` | Variante basée sur les **Docker Hardened Images** (Mission 4) → image `quiz-docker:dhi` |
| `.dockerignore` | Exclusion des fichiers inutiles ou sensibles du contexte de build |
| `resultats/` | Preuves : utilisateurs, tailles, couches, analyses de vulnérabilités |

Image publiée sur Docker Hub : **[`kemia44/quiz-docker:secure`](https://hub.docker.com/r/kemia44/quiz-docker)**

---

## Construire et lancer

```bash
# Image initiale
docker build -t quiz-docker:initial .
docker run -d --name quiz-initial -p 8093:3000 quiz-docker:initial

# Image sécurisée (avec les restrictions d'exécution)
docker build -f Dockerfile.secure -t quiz-docker:secure .
docker run -d --name quiz-secure -p 8092:3000 \
  --memory="256m" --cpus="0.5" \
  --read-only --tmpfs /tmp \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  quiz-docker:secure

# Image DHI (Mission 4) : nécessite "docker login dhi.io"
docker build -f Dockerfile.dhi -t quiz-docker:dhi .
docker run -d --name quiz-dhi -p 8094:3000 \
  --memory="256m" --cpus="0.5" \
  --read-only --tmpfs /tmp \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  quiz-docker:dhi
```

Accès : http://localhost:8093 (initiale), http://localhost:8092 (sécurisée), http://localhost:8094 (DHI).

---

## Mission 1 : Audit de l'image initiale

### Dockerfile audité

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package.json package-lock.json ./
COPY .. ./
RUN npm install
RUN npm install -g serve
RUN npm run build
RUN rm -fr node_modules
EXPOSE 3000
CMD ["serve", "-s", "dist"]
```

### État initial et risques identifiés

| Critère | Constat | Risque |
|---|---|---|
| Image de base | `node:18-alpine` | Node.js 18 est en **fin de vie depuis avril 2025** : plus aucun correctif de sécurité |
| Tag | `18-alpine` (tag flottant) | Le contenu de l'image peut changer d'un build à l'autre : builds non reproductibles |
| Utilisateur d'exécution | **`root`** (vérifié avec `docker container top`) | En cas de faille applicative, l'attaquant obtient les droits root dans le conteneur. Le noyau étant partagé avec l'hôte, l'impact d'une évasion est plus grave |
| Taille | **243 Mo** sur disque (60,2 Mo compressés) | Image lourde, plus longue à transférer, plus de composants |
| Couches | 4 `RUN` séparés | `rm -fr node_modules` n'allège pas l'image : `node_modules` reste stocké dans la couche du `npm install` (visible avec `docker image history`) |
| Composants embarqués | Code source, `npm`, outils de build, `node_modules` (dans les couches) | Surface d'attaque inutilement grande |
| `.dockerignore` | Absent | Risque d'embarquer `.git`, `.env`, `node_modules` locaux, logs… |
| `COPY .. ./` | Chemin trompeur | Fonctionne car Docker ne sort pas du contexte, mais la lecture est ambiguë |
| Ordre des instructions | `COPY` de tout le code **avant** `npm install` | Le cache des dépendances est invalidé à chaque modification du code |
| Ressources et privilèges | Aucune limite au lancement | Un conteneur compromis ou défaillant peut consommer toutes les ressources de l'hôte |
| Vulnérabilités (Docker Scout) | **13 critiques · 81 élevées · 72 moyennes · 14 faibles** (+1 non classée). L'image de base seule en apporte 7C / 42H / 31M / 11L ; le reste vient des paquets ajoutés (npm, `serve`, dépendances conservées dans les couches) | CVE connues, dont toutes les critiques et élevées sont corrigeables |
| Politiques Docker Scout | **2/7 respectées**, Health score **E (28 %)**. Alertes : *Image runs as the root user*, *Fixable critical or high vulnerabilities found* (13C / 81H), *High-profile vulnerabilities found* (1H) | Image non conforme aux bonnes pratiques de sécurité |

### Réponses aux questions

**L'image utilisée est-elle adaptée à une utilisation en production ?**
Non. Elle repose sur une version de Node.js qui n'est plus maintenue, elle s'exécute en `root` et elle embarque tout l'environnement de développement (code source, `npm`, dépendances de build) alors que la production n'a besoin que du résultat compilé.

**Quels composants sont réellement nécessaires pour exécuter l'application ?**
Uniquement le dossier `dist/` (HTML, CSS et JavaScript produits par `vite build`) et un serveur de fichiers statiques (`serve`, qui a besoin de Node.js). Le code source, `npm`, Vite et les dépendances de build ne servent qu'à la construction.

**Quels risques de sécurité identifiez-vous ?**
- exécution en `root` ;
- image de base obsolète, donc des CVE non corrigées ;
- surface d'attaque large (outils et fichiers inutiles) ;
- tag flottant, donc des builds non reproductibles ;
- absence de `.dockerignore` (fuite possible de fichiers sensibles) ;
- aucune limite de ressources ni restriction de privilèges à l'exécution.

**Quelles améliorations recommanderiez-vous en priorité ?**
1. Passer à une image de base maintenue, avec un tag précis.
2. Exécuter l'application avec un utilisateur non-root.
3. Utiliser un build multi-étapes pour ne livrer que `dist/` et le serveur.
4. Ajouter un `.dockerignore`.
5. Lancer le conteneur avec des limites de ressources et des privilèges réduits.
6. Analyser régulièrement les vulnérabilités.

---

## Mission 2 : Sécurisation

### Dockerfile sécurisé (`Dockerfile.secure`)

```dockerfile
# ---------- Étape 1 : construction ----------
FROM node:22.21.1-alpine3.22 AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# ---------- Étape 2 : production ----------
FROM node:22.21.1-alpine3.22 AS production

RUN npm install -g serve \
  && addgroup -S appgroup \
  && adduser -S -G appgroup appuser

WORKDIR /app
COPY --from=build --chown=appuser:appgroup /app/dist ./dist

USER appuser
EXPOSE 3000
CMD ["serve", "-s", "dist"]
```

### `.dockerignore`

```
.git
.env
node_modules
dist
*.log
Dockerfile*
```

### Application des 9 bonnes pratiques

| # | Bonne pratique | Mise en œuvre | Niveau |
|---|---|---|---|
| 1 | Image de base minimale | `node:…-alpine` + l'image finale ne contient que `dist/` et `serve` | Dockerfile |
| 2 | Pas d'exécution en root | Création de `appuser` / `appgroup`, instruction `USER appuser` | Dockerfile |
| 3 | `.dockerignore` | Exclusion de `.git`, `.env`, `node_modules`, `dist`, logs | Build |
| 4 | Tags précis | `node:22.21.1-alpine3.22` au lieu de `18-alpine` | Dockerfile |
| 5 | `COPY` plutôt que `ADD` | Uniquement des `COPY` | Dockerfile |
| 6 | Limiter ressources et privilèges | `--memory`, `--cpus`, `--read-only`, `--cap-drop ALL`, `no-new-privileges` | Exécution |
| 7 | Build multi-étapes | Étape `build` (compilation) jetée, étape `production` minimale | Dockerfile |
| 8 | Pas d'exposition du socket Docker | `/var/run/docker.sock` n'est jamais monté | Exécution |
| 9 | Vérification de la sécurité | Analyses Docker Scout avant et après (dossier `resultats/`) | Contrôle |

---

## Mission 3 : Comparaison avant / après

### Tableau comparatif

| Critère | `quiz-docker:initial` | `quiz-docker:secure` |
|---|---|---|
| Image de base | `node:18-alpine` (fin de vie) | `node:22.21.1-alpine3.22` (branche LTS maintenue) |
| Tag précis | Non | Oui |
| Taille sur disque | 243 Mo | 252 Mo |
| Taille compressée (contenu) | 60,2 Mo | 60,1 Mo |
| Utilisateur d'exécution | `root` | `appuser` |
| Outils de développement présents | Oui (sources, outils de build, `node_modules` dans les couches) | Non (seulement `dist/` et `serve`) |
| `.dockerignore` | Non | Oui |
| Multi-stage build | Non | Oui |
| Limitation des ressources | Non | 256 Mo de RAM, 0,5 CPU |
| Système de fichiers en lecture seule | Non | Oui (`--read-only`, `/tmp` en tmpfs) |
| Restriction des privilèges | Non | `--cap-drop ALL`, `no-new-privileges` |
| Accès au socket Docker | Non | Non |
| CVE critiques | 13 | **7** (−6) |
| CVE élevées | 81 | **57** (−24) |
| CVE moyennes | 72 | **35** (−37) |
| CVE faibles | 14 | **7** (−7) |
| Vulnérabilités « high-profile » | 1 | **0** |
| Politiques Docker Scout respectées | 2/7 | **3/7** |
| Health score Docker Scout | E (28 %) | **D (44 %)** |

Au total, l'image sécurisée passe de **180 à 106 CVE** (−41 %), et les politiques Scout *Default non-root user* et *No high-profile vulnerabilities* sont désormais respectées.

### Réponses aux questions d'analyse

**Quelles modifications ont apporté les améliorations les plus significatives ?**
- La **mise à jour de l'image de base** (Node.js 18 en fin de vie → Node.js 22 LTS) et le **build multi-étapes** font passer l'image de 180 à 106 CVE (−41 %), dont −6 critiques et −24 élevées. Le multi-étapes retire de l'image finale les dépendances de build et le code source, qui apportaient leurs propres vulnérabilités.
- Le **passage en non-root** ne change pas le nombre de CVE, mais il réduit fortement l'impact d'une compromission. C'est l'une des politiques Scout désormais respectées (*Default non-root user*).
- Les **restrictions d'exécution** (`--cap-drop ALL`, `--read-only`, `no-new-privileges`, limites mémoire et CPU) n'apparaissent pas dans le scan, qui analyse l'image et non le conteneur, mais elles limitent ce qu'un attaquant pourrait faire une fois dans le conteneur.

**La taille de l'image a-t-elle diminué ? Pourquoi ?**
Non, pas de façon significative : 60,2 Mo → 60,1 Mo compressés, et 243 Mo → 252 Mo sur disque. Deux effets se compensent :
- **ce qui allège :** grâce au multi-étapes, l'image finale ne contient plus le code source ni les couches de build (dont celle du `npm install`, que le `rm -fr node_modules` de l'image initiale ne supprimait pas) ;
- **ce qui alourdit :** l'image de base Node.js 22 est plus volumineuse que Node.js 18, et l'image finale embarque toujours Node.js complet, `npm` et `serve`.

Le gain de sécurité ne vient donc pas de la taille, mais du **contenu** : moins de composants vulnérables, un utilisateur non privilégié. Pour réduire réellement la taille, il faudrait une image finale sans `npm` (image distroless ou Docker Hardened Image, voir Mission 4), ou un serveur plus léger que Node.js pour servir des fichiers statiques.

**Quelles recommandations concernent le Dockerfile et lesquelles concernent l'exécution du conteneur ?**

| Dockerfile / build | Exécution (`docker run`) |
|---|---|
| Image de base minimale | Limitation mémoire (`--memory`) |
| Tag précis | Limitation CPU (`--cpus`) |
| Utilisateur non-root (`USER`) | Système de fichiers en lecture seule (`--read-only`) |
| `COPY` plutôt que `ADD` | Retrait des capacités Linux (`--cap-drop ALL`) |
| Build multi-étapes | Interdiction d'élévation de privilèges (`no-new-privileges`) |
| `.dockerignore` | Ne pas monter `/var/run/docker.sock` |

L'analyse des vulnérabilités s'applique aux deux, et doit être répétée régulièrement.

**Votre image est-elle désormais totalement sécurisée ? Justifiez votre réponse.**
Non. Les mesures appliquées **réduisent** les risques, mais ne les suppriment pas :
- de nouvelles CVE sont découvertes en permanence, donc une image saine aujourd'hui peut ne plus l'être demain ;
- l'image finale contient encore un shell, `npm` et le gestionnaire de paquets `apk`, qui pourraient être utilisés par un attaquant ;
- les conteneurs partagent le noyau de l'hôte : une faille du noyau reste un risque ;
- **il reste 106 CVE** (7 critiques, 57 élevées, 35 moyennes, 7 faibles), et Docker Scout indique que **toutes les critiques et élevées sont corrigeables** ;
- **le tag précis est déjà dépassé** : Scout signale *Outdated base images found* et recommande `node:22.23.5-alpine`, ce qui réduirait la part de l'image de base à 1C / 10H / 12M / 1L.

Ce dernier point montre la contrepartie d'un tag précis : il rend le build reproductible, mais il **fige aussi les vulnérabilités**. Il faut donc mettre à jour ce tag régulièrement et volontairement. La sécurité est un processus continu, pas un état final.

**Quelles mesures complémentaires proposeriez-vous pour un déploiement en production ?**
- Intégrer l'analyse de vulnérabilités (Docker Scout, Trivy) et le lint du Dockerfile (Hadolint) dans une **chaîne CI/CD**, avec blocage du déploiement en cas de CVE critique.
- **Reconstruire régulièrement** l'image pour intégrer les correctifs de l'image de base. Dans l'immédiat : passer à `node:22.23.5-alpine3.24`, comme le recommande Docker Scout (`docker scout recommendations quiz-docker:secure`). Un outil comme Dependabot ou Renovate peut proposer ces mises à jour automatiquement.
- Utiliser une **image durcie sans shell ni gestionnaire de paquets** (Docker Hardened Images, voir Mission 4).
- **Signer les images** et vérifier leur provenance (SBOM, attestations).
- Gérer les **secrets** hors de l'image (variables d'environnement injectées, gestionnaire de secrets).
- Placer l'application derrière un **reverse proxy** HTTPS et isoler les conteneurs dans des **réseaux dédiés**.
- **Surveiller** les conteneurs en production (logs, métriques, alertes).

---

## Mission 4 : Docker Hardened Images (DHI)

### Principe

Les Docker Hardened Images sont des images de base maintenues, corrigées et signées par Docker, disponibles sur le registre `dhi.io`. Elles existent en deux variantes :

| Variante | Exemple | Contenu | Usage |
|---|---|---|---|
| `-dev` | `dhi.io/node:22-alpine3.23-dev` | shell, `npm`, `apk`, utilisateur root | Étape de **construction** |
| runtime | `dhi.io/node:22-alpine3.23` | Node.js uniquement, **ni shell ni `npm`**, utilisateur **non-root** (`node`) | Étape de **production** |

### Adaptation de l'application (`Dockerfile.dhi`)

L'image runtime ne contient pas `npm`, donc `npm install -g serve` est impossible dans l'étape finale. `serve` est installé dans l'étape de construction (variante `-dev`), puis seul son dossier `node_modules` est copié. Le conteneur démarre avec `node` en forme exec, puisqu'il n'y a pas de shell. Aucun `USER` n'est nécessaire : l'image runtime est non-root par défaut.

```bash
docker login dhi.io
docker build -f Dockerfile.dhi -t quiz-docker:dhi .
```

### Comparaison

| Critère | `quiz-docker:secure` | `quiz-docker:dhi` |
|---|---|---|
| Image de base | `node:22.21.1-alpine3.22` (officielle) | `dhi.io/node:22-alpine3.23` (durcie) |
| Taille (disque / compressée) | 252 Mo / 60,1 Mo | Non mesurée |
| Utilisateur | `appuser` (créé manuellement) | `node` (non-root par défaut) |
| Shell dans l'image finale | Oui (`sh`) | Non |
| `npm` / `apk` dans l'image finale | Oui | Non |
| Signature, SBOM, provenance | Non fournis par nous | Fournis par Docker |
| CVE critiques / élevées | 7 / 57 | Non mesurées |
| CVE moyennes / faibles | 35 / 7 | Non mesurées |

Vérification de l'absence de shell :
```bash
docker exec -it quiz-dhi sh    # doit échouer : aucun shell dans l'image
```

### Conclusion

L'image DHI va plus loin que notre image sécurisée. Elle supprime le shell et les gestionnaires de paquets, ce qui prive un attaquant de ses outils même s'il parvient à exécuter du code. Elle est non-root par défaut, et elle est maintenue et signée par Docker, avec des correctifs suivis. Pour un déploiement en production, elle constitue la base la plus adaptée.

Contreparties :
- le débogage est plus difficile, faute de shell : il faut passer par des outils dédiés comme `docker debug` ;
- l'étape de build doit être adaptée (pas de `npm install -g` dans l'image finale) ;
- il faut un compte et une authentification sur le registre `dhi.io`.

> **Limite :** l'image `quiz-docker:dhi` n'a pas encore été construite et analysée dans le cadre de ce rendu. La comparaison ci-dessus s'appuie sur les caractéristiques documentées des Docker Hardened Images ; les mesures (taille et CVE) seront à confirmer avec `docker scout quickview quiz-docker:dhi`.
