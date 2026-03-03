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
- Effectue **deux requêtes** : domaine exact + tous les sous-domaines (`%.domain.com`), puis fusionne et déduplique les résultats
- Extrait tous les **FQDNs uniques** trouvés dans les certificats
- Isole les **wildcards** (`*.domain.com`) dans un fichier séparé (non soumis à la vérification DNS)
- Isole les **adresses e-mail** (SANs de type `rfc822Name`) dans un fichier séparé (non soumises à la vérification DNS)
- Vérifie la **résolution DNS** (enregistrements A, AAAA, CNAME) pour chaque FQDN
- Extrait les **adresses IPv4 et IPv6 uniques** dans des fichiers séparés
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

---

<a id="english"></a>
## 🇬🇧 English

### Description

`ct-checker.sh` is a bash script that queries **Certificate Transparency (CT) logs** for a given domain, extracts all associated FQDNs and verifies their DNS resolution.

It is designed to run on **any GNU/Linux distribution** and automatically installs its dependencies if they are missing.

### Features

- Queries **crt.sh**, which aggregates all public CT logs (Google, DigiCert, Cloudflare, Sectigo, Let's Encrypt, etc.)
- Performs **two queries**: exact domain + all subdomains (`%.domain.com`), then merges and deduplicates results
- Extracts all **unique FQDNs** found in certificates
- Isolates **wildcards** (`*.domain.com`) into a separate file (excluded from DNS verification)
- Isolates **email addresses** (`rfc822Name` SANs) into a separate file (excluded from DNS verification)
- Verifies **DNS resolution** (A, AAAA, CNAME records) for each FQDN
- Extracts **unique IPv4 and IPv6 addresses** into separate files
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
