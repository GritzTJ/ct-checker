<div align="center">

# ct-checker

*Certificate Transparency Log Checker*

**[🇫🇷 Français](#français) · [🇬🇧 English](#english)**

</div>

---

<a id="français"></a>
## 🇫🇷 Français

### Description

`ct-checker.sh` est un script bash qui interroge les logs de **Certificate Transparency (CT)** pour un domaine donné, extrait tous les FQDNs associés et vérifie leur résolution DNS.

Il est conçu pour fonctionner sur **n'importe quelle distribution GNU/Linux** et installe automatiquement ses dépendances si elles sont absentes.

### Fonctionnalités

- Interroge **crt.sh**, qui agrège l'ensemble des CT logs publics (Google, DigiCert, Cloudflare, Sectigo, Let's Encrypt, etc.)
- **Résilient aux pannes de crt.sh** : réessaie automatiquement le frontend web (les `HTTP 502` sont souvent transitoires), puis bascule en dernier recours sur la **base PostgreSQL publique de crt.sh** (`crt.sh:5432`) qui contourne le frontend web
- Effectue **deux requêtes** : domaine exact + tous les sous-domaines (`%.domain.com`), puis fusionne et déduplique les résultats
- Extrait tous les **FQDNs uniques** trouvés dans les certificats
- Isole les **wildcards** (`*.domain.com`) dans un fichier séparé (non soumis à la vérification DNS)
- Isole les **adresses e-mail** (SANs de type `rfc822Name`) dans un fichier séparé (non soumises à la vérification DNS)
- Vérifie la **résolution DNS** (enregistrements A, AAAA, CNAME) pour chaque FQDN
- Extrait les **adresses IPv4 et IPv6 uniques** dans des fichiers séparés
- Modes **stdout** (`-f`, `-4`, `-6`) : affiche les FQDNs/wildcards ou les IPs uniques sans écrire de fichiers sur disque
- Ne crée les fichiers de résultats **que s'ils contiennent des données** (aucun fichier vide)
- Génère un **rapport de synthèse** horodaté
- **Détecte automatiquement** la distribution et installe les dépendances manquantes

### Distributions supportées

| Gestionnaire | Distributions |
|---|---|
| `apt-get` | Debian, Ubuntu, et dérivés |
| `dnf` / `yum` | Fedora, RHEL, CentOS, Rocky, AlmaLinux |
| `pacman` | Arch Linux, Manjaro |
| `zypper` | openSUSE |
| `apk` | Alpine Linux |

### Dépendances

Installées automatiquement si absentes :

| Outil | Rôle |
|---|---|
| `curl` | Requêtes HTTP vers l'API crt.sh |
| `jq` | Parsing des réponses JSON |
| `dig` | Résolution DNS (fallback automatique : `nslookup`, `host`) |
| `psql` | **Installé à la demande** uniquement si le fallback PostgreSQL est déclenché (paquet `postgresql-client`) |

### Installation

```bash
git clone https://github.com/GritzTJ/ct-checker.git
cd ct-checker
chmod +x ct-checker.sh
```

### Utilisation

```
./ct-checker.sh -d <domaine> [OPTIONS]
```

| Option | Argument | Obligatoire | Description |
|---|---|---|---|
| `-d` | `DOMAINE` | **Oui** | FQDN cible à analyser |
| `-o` | `DOSSIER` | Non | Dossier de sortie (défaut : `./<domaine>`) |
| `-j` | `N` | Non | Résolutions DNS en parallèle (défaut : `10`) |
| `-f` | — | Non | Afficher uniquement les FQDNs et wildcards sur stdout (pas de fichiers) |
| `-4` | — | Non | Afficher uniquement les adresses IPv4 uniques sur stdout (pas de fichiers) |
| `-6` | — | Non | Afficher uniquement les adresses IPv6 uniques sur stdout (pas de fichiers) |
| `-v` | — | Non | Mode verbeux (détails des requêtes) |
| `-h` | — | Non | Afficher l'aide |

### Exemples

```bash
# Analyse basique
./ct-checker.sh -d example.com

# Avec dossier de sortie personnalisé
./ct-checker.sh -d example.com -o /tmp/resultats

# Mode verbeux
./ct-checker.sh -d example.com -v

# Parallélisme DNS personnalisé (utile pour les gros domaines)
./ct-checker.sh -d example.com -j 20

# FQDNs et wildcards uniquement (stdout)
./ct-checker.sh -d example.com -f

# Adresses IPv4 uniques uniquement (stdout)
./ct-checker.sh -d example.com -4

# Adresses IPv6 uniques uniquement (stdout)
./ct-checker.sh -d example.com -6
```

### Fichiers générés

Les résultats sont organisés par domaine et horodatés pour conserver l'historique des analyses :

```
./<domaine>/
└── <domaine>_<YYYYMMDD_HHMMSS>/
    ├── raw_ct_logs.json      Données JSON brutes issues de crt.sh
    ├── all_fqdns.txt         Tous les FQDNs uniques extraits
    ├── wildcards.txt         Entrées wildcard (si présentes)
    ├── emails.txt            Adresses e-mail extraites des SANs (si présentes)
    ├── dns_resolved.txt      FQDNs avec enregistrement DNS valide
    ├── dns_unresolved.txt    FQDNs sans enregistrement DNS (si présents)
    ├── ipv4_unique.txt       Adresses IPv4 uniques (si présentes)
    ├── ipv6_unique.txt       Adresses IPv6 uniques (si présentes)
    └── summary.txt           Rapport de synthèse
```

> `wildcards.txt`, `emails.txt`, `dns_unresolved.txt`, `ipv4_unique.txt` et `ipv6_unique.txt` ne sont créés que s'ils contiennent des données.

### Sources CT Logs

`crt.sh` agrège tous les logs Certificate Transparency publics, notamment :

- Google Argon / Xenon
- DigiCert Yeti
- Cloudflare Nimbus
- Sectigo
- Let's Encrypt Oak
- Trust Asia
- Et bien d'autres...

#### Tolérance aux pannes

`crt.sh` peut renvoyer des erreurs `HTTP 502`/`503` lorsqu'il est surchargé. Le script gère cela automatiquement, sans option à activer :

1. **Retry/backoff** sur le frontend web crt.sh (3 tentatives, délais croissants) — la plupart des 502 sont transitoires et disparaissent au 2ᵉ ou 3ᵉ essai.
2. Si le web reste indisponible, **bascule automatique** sur la base **PostgreSQL publique de crt.sh** (`crt.sh:5432`, utilisateur `guest`), qui sert les mêmes données mais contourne le frontend web. `psql` est alors installé à la demande.

> Les vrais logs CT (RFC 6962) ne sont pas interrogeables « par domaine » (journaux append-only sans index). Un agrégateur/index comme crt.sh est donc indispensable ; la base PostgreSQL de crt.sh en est l'accès direct. Elle renvoie l'historique complet (y compris les certificats expirés), le nombre de résultats peut donc être supérieur à celui du frontend web.

---

<a id="english"></a>
## 🇬🇧 English

### Description

`ct-checker.sh` is a bash script that queries **Certificate Transparency (CT) logs** for a given domain, extracts all associated FQDNs and verifies their DNS resolution.

It is designed to run on **any GNU/Linux distribution** and automatically installs its dependencies if they are missing.

### Features

- Queries **crt.sh**, which aggregates all public CT logs (Google, DigiCert, Cloudflare, Sectigo, Let's Encrypt, etc.)
- **Resilient to crt.sh outages**: automatically retries the web frontend (`HTTP 502` errors are often transient), then falls back as a last resort to the **public crt.sh PostgreSQL database** (`crt.sh:5432`), which bypasses the web frontend
- Performs **two queries**: exact domain + all subdomains (`%.domain.com`), then merges and deduplicates results
- Extracts all **unique FQDNs** found in certificates
- Isolates **wildcards** (`*.domain.com`) into a separate file (excluded from DNS verification)
- Isolates **email addresses** (`rfc822Name` SANs) into a separate file (excluded from DNS verification)
- Verifies **DNS resolution** (A, AAAA, CNAME records) for each FQDN
- Extracts **unique IPv4 and IPv6 addresses** into separate files
- **Stdout modes** (`-f`, `-4`, `-6`): display FQDNs/wildcards or unique IPs without writing files to disk
- Only creates result files **if they contain data** (no empty files)
- Generates a **timestamped summary report**
- **Automatically detects** the Linux distribution and installs missing dependencies

### Supported Distributions

| Package manager | Distributions |
|---|---|
| `apt-get` | Debian, Ubuntu, and derivatives |
| `dnf` / `yum` | Fedora, RHEL, CentOS, Rocky, AlmaLinux |
| `pacman` | Arch Linux, Manjaro |
| `zypper` | openSUSE |
| `apk` | Alpine Linux |

### Dependencies

Automatically installed if missing:

| Tool | Purpose |
|---|---|
| `curl` | HTTP requests to the crt.sh API |
| `jq` | JSON response parsing |
| `dig` | DNS resolution (automatic fallback: `nslookup`, `host`) |
| `psql` | **Installed on demand** only if the PostgreSQL fallback is triggered (package `postgresql-client`) |

### Installation

```bash
git clone https://github.com/GritzTJ/ct-checker.git
cd ct-checker
chmod +x ct-checker.sh
```

### Usage

```
./ct-checker.sh -d <domain> [OPTIONS]
```

| Option | Argument | Required | Description |
|---|---|---|---|
| `-d` | `DOMAIN` | **Yes** | Target FQDN to analyse |
| `-o` | `DIR` | No | Output directory (default: `./<domain>`) |
| `-j` | `N` | No | Parallel DNS resolutions (default: `10`) |
| `-f` | — | No | Display only FQDNs and wildcards on stdout (no files written) |
| `-4` | — | No | Display only unique IPv4 addresses on stdout (no files written) |
| `-6` | — | No | Display only unique IPv6 addresses on stdout (no files written) |
| `-v` | — | No | Verbose mode (query details) |
| `-h` | — | No | Show help |

### Examples

```bash
# Basic scan
./ct-checker.sh -d example.com

# Custom output directory
./ct-checker.sh -d example.com -o /tmp/results

# Verbose mode
./ct-checker.sh -d example.com -v

# Custom DNS parallelism (useful for large domains)
./ct-checker.sh -d example.com -j 20

# FQDNs and wildcards only (stdout)
./ct-checker.sh -d example.com -f

# Unique IPv4 addresses only (stdout)
./ct-checker.sh -d example.com -4

# Unique IPv6 addresses only (stdout)
./ct-checker.sh -d example.com -6
```

### Output Files

Results are organised by domain and timestamped to preserve the history of analyses:

```
./<domain>/
└── <domain>_<YYYYMMDD_HHMMSS>/
    ├── raw_ct_logs.json      Raw JSON data from crt.sh
    ├── all_fqdns.txt         All unique extracted FQDNs
    ├── wildcards.txt         Wildcard entries (if any)
    ├── emails.txt            Email addresses extracted from SANs (if any)
    ├── dns_resolved.txt      FQDNs with a valid DNS record
    ├── dns_unresolved.txt    FQDNs with no DNS record (if any)
    ├── ipv4_unique.txt       Unique IPv4 addresses (if any)
    ├── ipv6_unique.txt       Unique IPv6 addresses (if any)
    └── summary.txt           Summary report
```

> `wildcards.txt`, `emails.txt`, `dns_unresolved.txt`, `ipv4_unique.txt` and `ipv6_unique.txt` are only created if they contain data.

### CT Log Sources

`crt.sh` aggregates all public Certificate Transparency logs, including:

- Google Argon / Xenon
- DigiCert Yeti
- Cloudflare Nimbus
- Sectigo
- Let's Encrypt Oak
- Trust Asia
- And many more...

#### Fault tolerance

`crt.sh` may return `HTTP 502`/`503` errors when overloaded. The script handles this automatically, with no flag to enable:

1. **Retry/backoff** against the crt.sh web frontend (3 attempts, increasing delays) — most 502s are transient and clear on the 2nd or 3rd try.
2. If the web frontend stays unavailable, **automatic fallback** to the public **crt.sh PostgreSQL database** (`crt.sh:5432`, user `guest`), which serves the same data but bypasses the web frontend. `psql` is then installed on demand.

> The raw CT logs (RFC 6962) cannot be queried "by domain" (append-only logs with no domain index), so an aggregator/index like crt.sh is required; the crt.sh PostgreSQL database is its direct-access form. It returns the full history (including expired certificates), so the result count may be higher than the web frontend's.
