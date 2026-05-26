#!/bin/bash
# =============================================================================
# ct-checker.sh - Certificate Transparency Log Checker
# =============================================================================
# Interroge les CT logs pour un domaine donné, extrait tous les FQDNs
# et vérifie leur résolution DNS. Compatible avec toutes les distros GNU/Linux.
#
# Usage: ./ct-checker.sh -d example.com [-o /chemin/resultats] [-v]
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Métadonnées
# ---------------------------------------------------------------------------
readonly SCRIPT_NAME="ct-checker.sh"
readonly SCRIPT_VERSION="1.2.0"
readonly CRT_SH_API="https://crt.sh"
# Base PostgreSQL publique de crt.sh (fallback si le frontend web est en panne).
readonly CRT_SH_PG="postgresql://guest@crt.sh:5432/certwatch"

# ---------------------------------------------------------------------------
# Couleurs (désactivées si stdout n'est pas un terminal)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

# ---------------------------------------------------------------------------
# Globales
# ---------------------------------------------------------------------------
DOMAIN=""
OUTPUT_DIR=""
VERBOSE=false
STDOUT_MODE=""          # "" = normal, "f" = FQDNs/wildcards, "4" = IPv4 only, "6" = IPv6 only
STDOUT_TMPDIR=""        # tmpdir pour les modes stdout (nettoyé par trap EXIT)
DNS_TOOL=""
DNS_PARALLEL="${DNS_PARALLEL:-10}"   # nombre de résolutions DNS en parallèle (surchargeable via env ou -j)
OS_NAME="unknown"
PKG_MANAGER=""
_CLEANUP_FILES=()         # fichiers temporaires à supprimer en cas d'interruption
_CRTSH_CODE1="000"        # dernier code HTTP crt.sh (requête sous-domaines) — diagnostic
_CRTSH_CODE2="000"        # dernier code HTTP crt.sh (requête domaine exact) — diagnostic

# ---------------------------------------------------------------------------
# Fonctions de log
# ---------------------------------------------------------------------------
# Tous les logs vont sur stderr — stdout est réservé aux données du script
# (FQDNs, IPs en modes -f/-4/-6, ou rien en mode normal).
log_info()    { echo "${BLUE}[*]${NC} $*" >&2; }
log_success() { echo "${GREEN}[+]${NC} $*" >&2; }
log_warn()    { echo "${YELLOW}[!]${NC} $*" >&2; }
log_error()   { echo "${RED}[-]${NC} $*" >&2; }
log_debug()   { if $VERBOSE; then echo "${CYAN}[D]${NC} $*" >&2; fi; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
${BOLD}${SCRIPT_NAME} v${SCRIPT_VERSION}${NC}
Vérificateur de logs Certificate Transparency

${BOLD}USAGE:${NC}
    $0 -d <domaine> [OPTIONS]

${BOLD}OPTIONS:${NC}
    -d DOMAINE      Domaine cible (FQDN)                    [obligatoire]
    -o DOSSIER      Dossier de sortie (défaut: ./<domaine>)
    -j N            Résolutions DNS en parallèle (défaut: 10)
    -f              Afficher uniquement les FQDNs et wildcards (pas de fichiers)
    -4              Afficher uniquement les IPv4 uniques (pas de fichiers)
    -6              Afficher uniquement les IPv6 uniques (pas de fichiers)
    -v              Mode verbeux
    -h              Afficher cette aide

${BOLD}EXEMPLES:${NC}
    $0 -d example.com
    $0 -d example.com -o /tmp/resultats -v
    $0 -d example.com -j 20
    $0 -d example.com -f
    $0 -d example.com -4
    $0 -d example.com -6

${BOLD}FICHIERS DE SORTIE:${NC}
    <dossier>/<domaine>_<timestamp>/
    ├── raw_ct_logs.json      Données JSON brutes de crt.sh
    ├── all_fqdns.txt         Tous les FQDNs uniques extraits
    ├── wildcards.txt         Entrées wildcard (non vérifiées DNS)
    ├── dns_resolved.txt      FQDNs avec enregistrements DNS valides
    ├── dns_unresolved.txt    FQDNs sans enregistrement DNS (NXDOMAIN)
    └── summary.txt           Rapport de synthèse

${BOLD}SOURCES CT LOGS:${NC}
    crt.sh agrège tous les logs publics :
    Google Argon/Xenon, DigiCert Yeti, Cloudflare Nimbus,
    Sectigo, Let's Encrypt Oak, et bien d'autres.

EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Détection de l'OS et du gestionnaire de paquets
# ---------------------------------------------------------------------------
detect_os() {
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS_NAME="${PRETTY_NAME:-${ID:-unknown}}"
        log_debug "OS détecté : $OS_NAME"
    elif [ -f /etc/debian_version ]; then
        OS_NAME="Debian $(cat /etc/debian_version)"
    elif [ -f /etc/redhat-release ]; then
        OS_NAME=$(cat /etc/redhat-release)
    fi

    if   command -v apt-get &>/dev/null; then PKG_MANAGER="apt-get"
    elif command -v dnf     &>/dev/null; then PKG_MANAGER="dnf"
    elif command -v yum     &>/dev/null; then PKG_MANAGER="yum"
    elif command -v pacman  &>/dev/null; then PKG_MANAGER="pacman"
    elif command -v zypper  &>/dev/null; then PKG_MANAGER="zypper"
    elif command -v apk     &>/dev/null; then PKG_MANAGER="apk"
    else PKG_MANAGER=""
    fi

    log_debug "Gestionnaire de paquets : ${PKG_MANAGER:-aucun détecté}"
}

# Retourne le nom du paquet selon l'outil et le gestionnaire de paquets
get_package_name() {
    local tool="$1"
    case "$tool" in
        dig)
            case "$PKG_MANAGER" in
                apt-get)       echo "dnsutils"   ;;
                dnf|yum)       echo "bind-utils" ;;
                pacman)        echo "bind-tools"  ;;
                zypper)        echo "bind-utils"  ;;
                apk)           echo "bind-tools"  ;;
                *)             echo "dnsutils"    ;;
            esac ;;
        jq)   echo "jq"   ;;
        curl) echo "curl" ;;
        psql)
            case "$PKG_MANAGER" in
                apt-get)       echo "postgresql-client" ;;
                apk)           echo "postgresql-client" ;;
                dnf|yum)       echo "postgresql"        ;;
                pacman)        echo "postgresql"        ;;
                zypper)        echo "postgresql"        ;;
                *)             echo "postgresql-client" ;;
            esac ;;
        *)    echo "$tool" ;;
    esac
}

install_package() {
    local pkg="$1"
    local sudo_cmd="$2"

    case "$PKG_MANAGER" in
        apt-get) $sudo_cmd apt-get install -y "$pkg" >/dev/null 2>&1 ;;
        dnf)     $sudo_cmd dnf     install -y "$pkg" >/dev/null 2>&1 ;;
        yum)     $sudo_cmd yum     install -y "$pkg" >/dev/null 2>&1 ;;
        pacman)  $sudo_cmd pacman  -S --noconfirm "$pkg" >/dev/null 2>&1 ;;
        zypper)  $sudo_cmd zypper  install -y "$pkg" >/dev/null 2>&1 ;;
        apk)     $sudo_cmd apk     add "$pkg" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

check_dependencies() {
    # En mode -f, on n'utilise pas le DNS : pas besoin d'installer dig.
    local need_dns=true
    if [ "$STDOUT_MODE" = "f" ]; then
        need_dns=false
    fi

    log_info "Vérification des dépendances..."

    local missing_tools=()
    local dns_tools=("dig" "nslookup" "host")

    for tool in curl jq; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if $need_dns; then
        # Préférence : dig > nslookup > host (dig est le plus fiable)
        DNS_TOOL=""
        for tool in "${dns_tools[@]}"; do
            if command -v "$tool" &>/dev/null; then
                DNS_TOOL="$tool"
                break
            fi
        done

        if [ -z "$DNS_TOOL" ]; then
            missing_tools+=("dig")
        fi
    fi

    if [ ${#missing_tools[@]} -eq 0 ]; then
        if $need_dns; then
            log_success "Dépendances OK (outil DNS : $DNS_TOOL)"
        else
            log_success "Dépendances OK"
        fi
        return 0
    fi

    log_warn "Outils manquants : ${missing_tools[*]}"

    if [ -z "$PKG_MANAGER" ]; then
        log_error "Aucun gestionnaire de paquets détecté."
        log_error "Installez manuellement : ${missing_tools[*]}"
        exit 1
    fi

    # Détermine si sudo est nécessaire
    local sudo_cmd=""
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        if command -v sudo &>/dev/null; then
            sudo_cmd="sudo"
        else
            log_error "Droits root ou sudo requis pour installer les paquets."
            exit 1
        fi
    fi

    # Mise à jour des listes de paquets si nécessaire
    log_info "Mise à jour des listes de paquets..."
    case "$PKG_MANAGER" in
        apt-get) $sudo_cmd apt-get update -qq 2>/dev/null || true ;;
        pacman)  $sudo_cmd pacman -Sy --noconfirm 2>/dev/null || true ;;
        apk)     $sudo_cmd apk update 2>/dev/null || true ;;
    esac

    # Installation des outils manquants
    for tool in "${missing_tools[@]}"; do
        local pkg
        pkg=$(get_package_name "$tool")
        log_info "Installation de $tool (paquet : $pkg)..."

        if ! install_package "$pkg" "$sudo_cmd"; then
            log_error "Échec de l'installation de $pkg"
            exit 1
        fi

        if ! command -v "$tool" &>/dev/null; then
            log_error "$tool toujours introuvable après installation."
            exit 1
        fi

        log_success "$tool installé avec succès"
    done

    # Préfère dig dès qu'il est dispo (même si nslookup/host était déjà présent)
    if $need_dns && command -v dig &>/dev/null; then
        DNS_TOOL="dig"
    fi

    log_success "Toutes les dépendances sont prêtes"
}

# Installe un outil à la demande (chemin de secours uniquement, p.ex. psql pour le
# fallback PostgreSQL). Retourne 0 si l'outil est disponible, 1 sinon — SANS quitter
# le script, pour laisser l'appelant dégrader proprement.
ensure_tool() {
    local tool="$1"

    if command -v "$tool" &>/dev/null; then
        return 0
    fi

    log_warn "'$tool' absent — tentative d'installation (requis pour le fallback)..."

    if [ -z "$PKG_MANAGER" ]; then
        log_error "Aucun gestionnaire de paquets détecté : installez '$tool' manuellement."
        return 1
    fi

    local sudo_cmd=""
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        if command -v sudo &>/dev/null; then
            sudo_cmd="sudo"
        else
            log_error "Droits root ou sudo requis pour installer '$tool'."
            return 1
        fi
    fi

    case "$PKG_MANAGER" in
        apt-get) $sudo_cmd apt-get update -qq 2>/dev/null || true ;;
        pacman)  $sudo_cmd pacman -Sy --noconfirm 2>/dev/null || true ;;
        apk)     $sudo_cmd apk update 2>/dev/null || true ;;
    esac

    local pkg
    pkg=$(get_package_name "$tool")
    log_info "Installation de $tool (paquet : $pkg)..."

    if ! install_package "$pkg" "$sudo_cmd"; then
        log_error "Échec de l'installation de $pkg."
        return 1
    fi
    if ! command -v "$tool" &>/dev/null; then
        log_error "$tool toujours introuvable après installation."
        return 1
    fi

    log_success "$tool installé avec succès"
    return 0
}

# ---------------------------------------------------------------------------
# Requête des CT logs : crt.sh (web) avec retry, puis fallback PostgreSQL crt.sh
# ---------------------------------------------------------------------------
# Source primaire : API web crt.sh (2 requêtes : sous-domaines + domaine exact).
# Écrit le JSON fusionné dans $output_file et retourne 0 si OK, 1 sinon.
# Ne quitte PAS le script : l'orchestrateur décide du retry/fallback.
# Renseigne _CRTSH_CODE1/2 (codes HTTP) pour le diagnostic global.
_fetch_crtsh() {
    local domain="$1"
    local output_file="$2"

    local tmp1 tmp2
    tmp1=$(mktemp -t ct_check.XXXXXX)
    tmp2=$(mktemp -t ct_check.XXXXXX)
    _CLEANUP_FILES+=("$tmp1" "$tmp2")

    # Timeouts serrés pour éviter d'attendre 3+ minutes quand crt.sh rame
    # ou renvoie des 5xx : 1ère tentative 45s, 1 retry, ~60s max au total.
    local -a curl_opts=(
        -s --max-time 45 --retry 1 --retry-delay 3 --retry-max-time 60
        -H "Accept: application/json"
    )

    # Requête 1 : sous-domaines (%.domain.com)
    log_info "Requête 1/2 : sous-domaines (%.${domain})..."
    local resp_code1 resp_code2
    resp_code1=$(curl "${curl_opts[@]}" -o "$tmp1" -w "%{http_code}" \
        "${CRT_SH_API}/?q=%25.${domain}&output=json" 2>/dev/null) || resp_code1="000"
    if [ "$resp_code1" != "200" ]; then
        log_warn "crt.sh a retourné HTTP $resp_code1 pour la requête sous-domaines"
    fi

    # Requête 2 : domaine exact
    log_info "Requête 2/2 : domaine exact (${domain})..."
    resp_code2=$(curl "${curl_opts[@]}" -o "$tmp2" -w "%{http_code}" \
        "${CRT_SH_API}/?q=${domain}&output=json" 2>/dev/null) || resp_code2="000"
    if [ "$resp_code2" != "200" ]; then
        log_warn "crt.sh a retourné HTTP $resp_code2 pour la requête domaine exact"
    fi

    _CRTSH_CODE1="$resp_code1"
    _CRTSH_CODE2="$resp_code2"

    # Validation JSON
    local valid1=false valid2=false
    if jq -e 'if type == "array" then . else error end' "$tmp1" &>/dev/null; then valid1=true; fi
    if jq -e 'if type == "array" then . else error end' "$tmp2" &>/dev/null; then valid2=true; fi

    if ! $valid1 && ! $valid2; then
        rm -f "$tmp1" "$tmp2"
        return 1
    fi

    # Fusion et déduplication par ID de certificat
    if $valid1 && $valid2; then
        jq -s 'flatten | unique_by(.id) | sort_by(.id)' "$tmp1" "$tmp2" > "$output_file"
    elif $valid1; then
        jq '.' "$tmp1" > "$output_file"
    else
        jq '.' "$tmp2" > "$output_file"
    fi

    rm -f "$tmp1" "$tmp2"
    return 0
}

# Fallback : base PostgreSQL publique de crt.sh (crt.sh:5432). Même jeu de données
# que le frontend web, mais le contourne — utile quand le web renvoie des 5xx.
# Produit EXACTEMENT le schéma attendu par extract_fqdns : un tableau JSON d'objets
# {id, name_value}, un par certificat, name_value = SANs du domaine joints par \n.
# Retourne 0 (tableau JSON valide écrit, éventuellement vide) ou 1 (échec).
_fetch_crtsh_pg() {
    local domain="$1"
    local output_file="$2"

    if ! ensure_tool psql; then
        log_error "Le client PostgreSQL (psql) est requis pour le fallback mais indisponible."
        return 1
    fi

    log_info "Interrogation de la base PostgreSQL crt.sh (peut prendre 1–2 min sur les gros domaines)..."

    local err_file
    err_file=$(mktemp -t ct_pg.XXXXXX)
    _CLEANUP_FILES+=("$err_file")

    # Le domaine est passé en variable psql (:'dom') → aucune injection SQL possible.
    # L'index plein-texte (plainto_tsquery @@ identities) assure la rapidité ; on
    # regroupe par certificat et on ne garde que les identités du domaine cible
    # (dNSName, commonName 2.5.4.3, e-mail rfc822Name) pour éviter les SANs étrangers.
    # statement_timeout fixé côté serveur ; sed ne garde que la valeur JSON (purge
    # l'étiquette « SET »). « || true » neutralise pipefail : on valide via jq ensuite.
    PGCONNECT_TIMEOUT=15 psql "$CRT_SH_PG" -X -A -t -q \
        -v ON_ERROR_STOP=1 -v dom="$domain" 2>"$err_file" <<'SQL' | sed -n '/^\[/,$p' > "$output_file" || true
SET statement_timeout TO '120000';
SELECT coalesce(json_agg(t), '[]'::json) FROM (
  SELECT certificate_id AS id, string_agg(DISTINCT name_value, E'\n') AS name_value
  FROM certificate_and_identities
  WHERE plainto_tsquery('certwatch', :'dom') @@ identities(CERTIFICATE)
    AND name_type IN ('san:dNSName','san:rfc822Name','2.5.4.3')
    AND (lower(name_value) = lower(:'dom')
         OR lower(name_value) LIKE lower('%.' || :'dom')
         OR lower(name_value) LIKE lower('%@' || :'dom'))
  GROUP BY certificate_id
) t;
SQL

    local pg_err=""
    pg_err=$(cat "$err_file" 2>/dev/null || true)
    rm -f "$err_file"

    if ! jq -e 'if type == "array" then . else error end' "$output_file" &>/dev/null; then
        log_error "Échec de la requête PostgreSQL crt.sh."
        [ -n "$pg_err" ] && log_error "Détail : ${pg_err}"
        return 1
    fi

    local n
    n=$(jq 'length' "$output_file")
    if [ "$n" -eq 0 ]; then
        log_warn "Aucun certificat trouvé pour ${domain} dans la base PostgreSQL crt.sh."
    fi
    return 0
}

# Orchestrateur : crt.sh web (avec retry/backoff sur 5xx/000 transitoires),
# puis bascule automatique vers la base PostgreSQL crt.sh si le web reste muet.
query_ct_logs() {
    local domain="$1"
    local output_file="$2"

    log_info "Interrogation des CT logs via crt.sh..."
    log_info "Agrège : Google, DigiCert, Cloudflare Nimbus, Sectigo, Let's Encrypt, etc."
    log_info "(crt.sh peut être lent ou indisponible — patience, max ~60s par requête)"

    # 1) Source primaire : API web crt.sh, avec retry/backoff (les 502 sont souvent
    #    transitoires : ils reviennent vite, le retry suffit dans la plupart des cas).
    local attempt max_attempts=3
    local -a backoff=(5 15)   # secondes d'attente avant la tentative suivante
    for ((attempt=1; attempt<=max_attempts; attempt++)); do
        if [ "$attempt" -gt 1 ]; then
            log_info "crt.sh — tentative ${attempt}/${max_attempts}..."
        fi
        if _fetch_crtsh "$domain" "$output_file"; then
            local count
            count=$(jq 'length' "$output_file")
            log_success "${count} entrées de certificats trouvées dans les CT logs"
            return 0
        fi
        if [ "$attempt" -lt "$max_attempts" ]; then
            local delay="${backoff[$((attempt-1))]:-15}"
            log_warn "Réponse crt.sh invalide (HTTP ${_CRTSH_CODE1}/${_CRTSH_CODE2}). Nouvel essai dans ${delay}s..."
            sleep "$delay"
        fi
    done

    # 2) Fallback : base PostgreSQL publique de crt.sh (contourne le frontend web).
    log_warn "crt.sh (web) indisponible après ${max_attempts} tentatives — bascule vers la base PostgreSQL crt.sh."
    if _fetch_crtsh_pg "$domain" "$output_file"; then
        local count
        count=$(jq 'length' "$output_file")
        log_success "${count} certificats récupérés via la base PostgreSQL crt.sh"
        return 0
    fi

    # 3) Échec total : diagnostic puis sortie.
    log_error "Aucune source CT n'a pu être interrogée (web + PostgreSQL)."
    if [[ "$_CRTSH_CODE1" =~ ^5 ]] || [[ "$_CRTSH_CODE2" =~ ^5 ]]; then
        log_error "crt.sh (web) semble en panne (HTTP 5xx) et le fallback PostgreSQL a échoué."
        log_error "Status : https://crt.sh/  ou  https://groups.google.com/g/crtsh"
    elif [ "$_CRTSH_CODE1" = "000" ] && [ "$_CRTSH_CODE2" = "000" ]; then
        log_error "Aucune réponse réseau. Vérifiez votre connexion internet."
    else
        log_error "Codes HTTP crt.sh reçus : ${_CRTSH_CODE1} / ${_CRTSH_CODE2}"
    fi
    exit 1
}

# ---------------------------------------------------------------------------
# Extraction des FQDNs depuis les données CT
# ---------------------------------------------------------------------------
extract_fqdns() {
    local ct_file="$1"
    local fqdns_file="$2"
    local wildcards_file="$3"
    local emails_file="$4"

    log_info "Extraction des FQDNs uniques depuis les données CT..."

    # name_value contient les SANs séparés par \n ; jq -r restitue ces \n en newlines.
    # On nettoie (trim, dédup) puis on classe en 3 catégories en une seule passe awk.
    local tmp_names
    tmp_names=$(mktemp -t ct_all_names.XXXXXX)
    _CLEANUP_FILES+=("$tmp_names")

    jq -r '.[].name_value' "$ct_file" \
        | awk '{ gsub(/^[ \t]+|[ \t]+$/, ""); if ($0 != "") print }' \
        | sort -u > "$tmp_names"

    # Crée les fichiers (vides) pour que les wc/test ultérieurs ne plantent pas.
    : > "$fqdns_file"
    : > "$wildcards_file"
    : > "$emails_file"

    # Classement en une seule passe :
    # - e-mails (contiennent @) — SANs de type rfc822Name
    # - wildcards (^*.) — hors e-mails
    # - FQDNs normaux — ni e-mail, ni wildcard
    awk -v f_fqdn="$fqdns_file" -v f_wc="$wildcards_file" -v f_mail="$emails_file" '
        /@/      { print > f_mail; next }
        /^\*\./  { print > f_wc;   next }
                 { print > f_fqdn }
    ' "$tmp_names"

    rm -f "$tmp_names"

    local fqdn_count wildcard_count email_count
    fqdn_count=$(wc -l < "$fqdns_file" | tr -d ' ')
    wildcard_count=$(wc -l < "$wildcards_file" | tr -d ' ')
    email_count=$(wc -l < "$emails_file" | tr -d ' ')

    # Supprime les fichiers vides
    if [ "$wildcard_count" -eq 0 ]; then rm -f "$wildcards_file"; fi
    if [ "$email_count" -eq 0 ];    then rm -f "$emails_file";    fi

    log_success "${fqdn_count} FQDNs uniques extraits"
    if [ "$wildcard_count" -gt 0 ]; then
        log_success "${wildcard_count} entrées wildcard isolées (stockées séparément)"
    else
        log_info "Aucun wildcard trouvé"
    fi
    if [ "$email_count" -gt 0 ]; then
        log_success "${email_count} adresses e-mail isolées (stockées dans emails.txt)"
    else
        log_info "Aucune adresse e-mail trouvée"
    fi
}

# ---------------------------------------------------------------------------
# Résolution DNS selon l'outil disponible
# ---------------------------------------------------------------------------

# Regex IPv4 / IPv6 stricts. On utilise [.] plutôt que \. pour qu'awk ne râle pas
# quand le pattern est passé via -v (où awk évalue les escapes).
readonly RE_IPV4='^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$'
readonly RE_IPV6='^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$'

# Retourne les enregistrements DNS séparés par des virgules, ou chaîne vide.
# Toutes les pipes utilisent || true pour rester compatibles avec set -e (grep
# retourne 1 quand aucun match).
_resolve_dig() {
    local fqdn="$1" type="$2"
    local raw
    raw=$(dig +short +timeout=5 +tries=2 "$type" "$fqdn" 2>/dev/null \
        | { grep -v '^;' || true; } | { grep -v '^$' || true; })
    # Pour A et AAAA, ne garder que les adresses IP (exclure les CNAME intermédiaires)
    case "$type" in
        A)    raw=$(echo "$raw" | { grep -E "$RE_IPV4" || true; }) ;;
        AAAA) raw=$(echo "$raw" | { grep -E "$RE_IPV6" || true; }) ;;
    esac
    echo "$raw" | { grep -v '^$' || true; } | tr '\n' ',' | sed 's/,$//'
}

_resolve_nslookup() {
    local fqdn="$1" type="$2"
    local raw
    raw=$(nslookup -type="$type" -timeout=5 "$fqdn" 2>/dev/null \
        | { grep -Ev '^(Server|Address|$|;)' || true; } \
        | awk '/^[^*]/ {print $NF}')
    case "$type" in
        A)    raw=$(echo "$raw" | { grep -E "$RE_IPV4" || true; }) ;;
        AAAA) raw=$(echo "$raw" | { grep -E "$RE_IPV6" || true; }) ;;
    esac
    echo "$raw" | { grep -v '^$' || true; } | tr '\n' ',' | sed 's/,$//'
}

_resolve_host() {
    local fqdn="$1" type="$2"
    local raw
    raw=$(host -t "$type" -W 5 "$fqdn" 2>/dev/null \
        | { grep -iv 'nxdomain\|not found\|servfail\|timed out' || true; } \
        | awk '{print $NF}')
    case "$type" in
        A)    raw=$(echo "$raw" | { grep -E "$RE_IPV4" || true; }) ;;
        AAAA) raw=$(echo "$raw" | { grep -E "$RE_IPV6" || true; }) ;;
    esac
    echo "$raw" | { grep -v '^$' || true; } | tr '\n' ',' | sed 's/,$//'
}

# Effectue la vérification DNS d'un FQDN
# Retourne : "true|a_records|aaaa_records|cname_record"
check_dns() {
    local fqdn="$1"
    local a_records="" aaaa_records="" cname_record=""

    case "$DNS_TOOL" in
        dig)
            a_records=$(   _resolve_dig      "$fqdn" "A"     )
            aaaa_records=$(  _resolve_dig      "$fqdn" "AAAA"  )
            cname_record=$(  _resolve_dig      "$fqdn" "CNAME" )
            ;;
        nslookup)
            a_records=$(   _resolve_nslookup "$fqdn" "A"     )
            aaaa_records=$(  _resolve_nslookup "$fqdn" "AAAA"  )
            cname_record=$(  _resolve_nslookup "$fqdn" "CNAME" )
            ;;
        host)
            a_records=$(   _resolve_host     "$fqdn" "A"     )
            aaaa_records=$(  _resolve_host     "$fqdn" "AAAA"  )
            cname_record=$(  _resolve_host     "$fqdn" "CNAME" )
            ;;
    esac

    local resolved=false
    if [ -n "$a_records" ] || [ -n "$aaaa_records" ] || [ -n "$cname_record" ]; then
        resolved=true
    fi

    echo "${resolved}|${a_records}|${aaaa_records}|${cname_record}"
}

# ---------------------------------------------------------------------------
# Worker DNS — appelé en parallèle via xargs.
# Lit un FQDN en argument, écrit sur stdout :  status|fqdn|a_csv|aaaa_csv|cname
# ---------------------------------------------------------------------------
_dns_worker_csv() {
    local fqdn="$1"
    [ -z "$fqdn" ] && return 0
    local result is_resolved a aaaa cname
    result=$(check_dns "$fqdn")
    IFS='|' read -r is_resolved a aaaa cname <<< "$result"
    echo "${is_resolved}|${fqdn}|${a}|${aaaa}|${cname}"
}

# ---------------------------------------------------------------------------
# Vérification DNS parallélisée (xargs -P)
# Le rendu tabulaire multi-ligne est ensuite produit en une passe awk.
# ---------------------------------------------------------------------------
verify_dns() {
    local fqdns_file="$1"
    local resolved_file="$2"
    local unresolved_file="$3"

    local total
    total=$(grep -c . "$fqdns_file" 2>/dev/null || echo 0)
    local parallel="${DNS_PARALLEL:-10}"

    log_info "Vérification DNS de ${total} FQDNs (outil : ${DNS_TOOL}, parallélisme : ${parallel})..."

    # CSV intermédiaire — chaque worker imprime une ligne ; pour des lignes
    # < PIPE_BUF (4 Ko) l'écriture est atomique sur Linux, pas besoin de lock.
    local tmp_csv
    tmp_csv=$(mktemp -t ct_dns_csv.XXXXXX)
    _CLEANUP_FILES+=("$tmp_csv")

    # Variables et fonctions à propager aux sous-shells xargs
    export DNS_TOOL RE_IPV4 RE_IPV6
    export -f _resolve_dig _resolve_nslookup _resolve_host check_dns _dns_worker_csv

    if [ "$total" -gt 0 ]; then
        # -P : parallélisme  -I {} : substitution (implique -n 1)
        xargs -P "$parallel" -I {} bash -c '_dns_worker_csv "$@"' _ {} \
            < "$fqdns_file" > "$tmp_csv"
    fi

    # Compte les résultats
    local resolved_count unresolved_count
    resolved_count=$(awk -F'|' '$1=="true"'  "$tmp_csv" | wc -l | tr -d ' ')
    unresolved_count=$(awk -F'|' '$1=="false"' "$tmp_csv" | wc -l | tr -d ' ')

    # Tri alphabétique par FQDN — rapport déterministe et lisible
    sort -t'|' -k2,2 "$tmp_csv" -o "$tmp_csv"

    # En-tête commun
    local header separator
    header=$(printf "%-60s | %-35s | %-40s | %s" "FQDN" "A (IPv4)" "AAAA (IPv6)" "CNAME")
    separator=$(printf '%0.s-' {1..155})

    if [ "$resolved_count" -gt 0 ]; then
        {
            echo "# DNS Verification Results (RESOLVED) - $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
            echo "# Domaine : $DOMAIN | Outil DNS : $DNS_TOOL"
            echo "$separator"
            echo "$header"
            echo "$separator"
            awk -F'|' -v sep="$separator" '
                $1=="true" {
                    fqdn=$2; a=$3; aaaa=$4; cname=$5
                    n_a    = (a    == "") ? 0 : split(a,    a_arr,    ",")
                    n_aaaa = (aaaa == "") ? 0 : split(aaaa, aaaa_arr, ",")
                    max = (n_a > n_aaaa) ? n_a : n_aaaa
                    if (max == 0) max = 1
                    printf "%-60s | %-35s | %-40s | %s\n", \
                        fqdn, \
                        (n_a    > 0 ? a_arr[1]    : "N/A"), \
                        (n_aaaa > 0 ? aaaa_arr[1] : "N/A"), \
                        (cname != ""  ? cname     : "N/A")
                    for (i = 2; i <= max; i++) {
                        printf "%-60s | %-35s | %-40s |\n", \
                            "", \
                            (i <= n_a    ? a_arr[i]    : ""), \
                            (i <= n_aaaa ? aaaa_arr[i] : "")
                    }
                    if (max > 1) print sep
                }
            ' "$tmp_csv"
        } > "$resolved_file"
    fi

    if [ "$unresolved_count" -gt 0 ]; then
        {
            echo "# DNS Verification Results (UNRESOLVED) - $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
            echo "# Domaine : $DOMAIN | Outil DNS : $DNS_TOOL"
            echo "$separator"
            echo "$header"
            echo "$separator"
            awk -F'|' '$1=="false" {
                printf "%-60s | %-35s | %-40s | %s\n", $2, "N/A", "N/A", "N/A"
            }' "$tmp_csv"
        } > "$unresolved_file"
    fi

    rm -f "$tmp_csv"

    log_success "DNS : ${resolved_count} résolus, ${unresolved_count} non résolus (sur ${total})"

    echo "${total}|${resolved_count}|${unresolved_count}"
}

# ---------------------------------------------------------------------------
# Génération du rapport de synthèse
# ---------------------------------------------------------------------------
generate_summary() {
    local domain="$1"
    local run_dir="$2"
    local cert_count="$3"
    local fqdn_count="$4"
    local wildcard_count="$5"
    local email_count="$6"
    local dns_stats="$7"
    local summary_file="$8"

    local dns_total dns_resolved dns_unresolved
    IFS='|' read -r dns_total dns_resolved dns_unresolved <<< "$dns_stats"

    local resolution_rate="N/A"
    if [ "$dns_total" -gt 0 ] 2>/dev/null; then
        resolution_rate=$(awk -v r="$dns_resolved" -v t="$dns_total" 'BEGIN {printf "%.1f%%", (r / t) * 100}')
    fi

    # Lignes conditionnelles wildcards et emails
    local wildcard_line email_line
    if [ "$wildcard_count" -gt 0 ]; then
        wildcard_line="  Wildcards      : ${wildcard_count} (stockés dans wildcards.txt, non vérifiés DNS)"
    else
        wildcard_line="  Wildcards      : Aucun"
    fi
    if [ "$email_count" -gt 0 ]; then
        email_line="  Adresses e-mail: ${email_count} (stockées dans emails.txt, non vérifiées DNS)"
    else
        email_line="  Adresses e-mail: Aucune"
    fi

    # Chiffres DNS en largeur fixe pour alignement cohérent
    local fmt_total fmt_resolved fmt_unresolved
    printf -v fmt_total     "%4d" "$dns_total"
    printf -v fmt_resolved  "%4d" "$dns_resolved"
    printf -v fmt_unresolved "%4d" "$dns_unresolved"

    # Liste des fichiers pré-calculée (summary.txt étant en cours d'écriture,
    # on l'ajoute manuellement pour éviter l'affichage "0 octet").
    # Utilisation de printf -v pour préserver les sauts de ligne ($() les supprimerait).
    local file_list="" _entry
    local _known_files=(raw_ct_logs.json all_fqdns.txt wildcards.txt emails.txt dns_resolved.txt dns_unresolved.txt ipv4_unique.txt ipv6_unique.txt)
    for _f in "${_known_files[@]}"; do
        local _fp="${run_dir}/${_f}"
        if [ -f "$_fp" ]; then
            local _lc
            _lc=$(grep -c . "$_fp" 2>/dev/null || echo 0)
            printf -v _entry "  %-38s %s lignes\n" "$_f" "$_lc"
            file_list+="$_entry"
        fi
    done
    printf -v _entry "  %-38s %s\n" "summary.txt" "(rapport de synthèse)"
    file_list+="$_entry"

    cat > "$summary_file" <<EOF
================================================================================
  RAPPORT - Certificate Transparency Log Checker v${SCRIPT_VERSION}
================================================================================
  Domaine cible  : $domain
  Date           : $(date -u '+%Y-%m-%d %H:%M:%S UTC')
  OS             : ${OS_NAME}
  Outil DNS      : ${DNS_TOOL}
  Dossier        : ${run_dir}
================================================================================

  RÉSULTATS
  ---------
  Certificats    : ${cert_count} entrées trouvées dans les CT logs
  FQDNs uniques  : ${fqdn_count} (wildcards et e-mails exclus)
${wildcard_line}
${email_line}

================================================================================

  VÉRIFICATION DNS
  ----------------
  FQDNs vérifiés :${fmt_total}
  Résolus        :${fmt_resolved}  → enregistrement(s) DNS valide(s)
  Non résolus    :${fmt_unresolved}  → NXDOMAIN ou aucun enregistrement
  Taux résolution: ${resolution_rate}

================================================================================

  FICHIERS GÉNÉRÉS
  ----------------
${file_list}
================================================================================
EOF

    log_success "Rapport de synthèse généré : $summary_file"
}

# ---------------------------------------------------------------------------
# Parsing des arguments
# ---------------------------------------------------------------------------
parse_args() {
    [ $# -eq 0 ] && usage

    while getopts "d:o:j:f46vh" opt; do
        case $opt in
            d) DOMAIN="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            j) DNS_PARALLEL="$OPTARG" ;;
            f) STDOUT_MODE="f" ;;
            4) STDOUT_MODE="4" ;;
            6) STDOUT_MODE="6" ;;
            v) VERBOSE=true ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    # Valide DNS_PARALLEL
    if ! [[ "$DNS_PARALLEL" =~ ^[0-9]+$ ]] || [ "$DNS_PARALLEL" -lt 1 ]; then
        log_error "Le parallélisme (-j) doit être un entier ≥ 1 (reçu : $DNS_PARALLEL)"
        exit 1
    fi

    if [ -z "$DOMAIN" ]; then
        log_error "Le domaine (-d) est obligatoire."
        usage
    fi

    # Validation basique du format FQDN
    if ! echo "$DOMAIN" | grep -qE \
        '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'; then
        log_error "Format de domaine invalide : $DOMAIN"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Nettoyage en cas d'interruption
# ---------------------------------------------------------------------------
cleanup() {
    local sig="${1:-INT}"
    if [ ${#_CLEANUP_FILES[@]} -gt 0 ]; then
        rm -f "${_CLEANUP_FILES[@]}" 2>/dev/null || true
    fi
    _CLEANUP_FILES=()
    printf "\r%80s\r" "" >&2
    log_warn "Interruption détectée. Fichiers temporaires nettoyés."
    # Le trap par défaut continue l'exécution après le handler ; on doit donc
    # forcer un exit ici, sinon le script poursuit avec un état incohérent
    # (curl interrompu, fichiers temp absents, etc.).
    case "$sig" in
        TERM) exit 143 ;;
        *)    exit 130 ;;
    esac
}
trap 'cleanup INT'  INT
trap 'cleanup TERM' TERM

# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    # --- Mode stdout (-f / -4 / -6) : tout dans un tmpdir, affichage sur stdout ---
    if [ -n "$STDOUT_MODE" ]; then
        STDOUT_TMPDIR=$(mktemp -d -t ct_checker.XXXXXX)
        trap 'rm -rf "$STDOUT_TMPDIR"' EXIT
        local tmpdir="$STDOUT_TMPDIR"

        detect_os
        check_dependencies

        log_info "Domaine cible : ${BOLD}${DOMAIN}${NC}"
        case "$STDOUT_MODE" in
            f) log_info "Mode : FQDNs et wildcards uniquement (pas de fichiers sur disque)" ;;
            *) log_info "Mode : IPv${STDOUT_MODE} uniquement (pas de fichiers sur disque)" ;;
        esac

        # Étape 1 : CT logs
        local raw_ct_file="${tmpdir}/raw_ct_logs.json"
        query_ct_logs "$DOMAIN" "$raw_ct_file"

        # Étape 2 : extraction FQDNs
        local all_fqdns_file="${tmpdir}/all_fqdns.txt"
        local wildcards_file="${tmpdir}/wildcards.txt"
        extract_fqdns "$raw_ct_file" "$all_fqdns_file" "$wildcards_file" "${tmpdir}/emails.txt"

        if [ "$STDOUT_MODE" = "f" ]; then
            # Afficher FQDNs et wildcards sur stdout
            if [ -f "$all_fqdns_file" ]; then cat "$all_fqdns_file"; fi
            if [ -f "$wildcards_file" ]; then cat "$wildcards_file"; fi
            return 0
        fi

        local fqdn_count
        fqdn_count=$(wc -l < "$all_fqdns_file" | tr -d ' ')
        log_info "${fqdn_count} FQDNs à vérifier"

        # Étape 3 : vérification DNS
        local dns_resolved_file="${tmpdir}/dns_resolved.txt"
        verify_dns "$all_fqdns_file" "$dns_resolved_file" "${tmpdir}/dns_unresolved.txt" > /dev/null

        # Étape 4 : extraction et affichage des IPs
        if [ -f "$dns_resolved_file" ]; then
            if [ "$STDOUT_MODE" = "4" ]; then
                awk -F '|' -v re="$RE_IPV4" 'NR>5 { gsub(/^ +| +$/, "", $2); if ($2 ~ re) print $2 }' \
                    "$dns_resolved_file" | sort -u
            else
                awk -F '|' -v re="$RE_IPV6" 'NR>5 { gsub(/^ +| +$/, "", $3); if ($3 ~ re) print $3 }' \
                    "$dns_resolved_file" | sort -u
            fi
        fi

        return 0
    fi

    # --- Mode normal : écriture de tous les fichiers ---

    # Dossier de sortie par défaut = nom du domaine si -o non fourni
    [ -z "$OUTPUT_DIR" ] && OUTPUT_DIR="./${DOMAIN}"

    local _border="═══════════════════════════════════════════════════════════════"
    local _title="Certificate Transparency Log Checker  v${SCRIPT_VERSION}"
    local _inner=63   # largeur visuelle fixe (63 × ═) — ${#} compterait des octets en locale C
    local _tlen=${#_title}
    local _pl=$(( (_inner - _tlen) / 2 ))
    local _pr=$(( _inner - _tlen - _pl ))
    printf "${BOLD}${CYAN}╔%s╗\n║%*s%s%*s║\n╚%s╝${NC}\n\n" \
        "$_border" $_pl "" "$_title" $_pr "" "$_border"

    log_info "Domaine cible : ${BOLD}${DOMAIN}${NC}"

    detect_os
    log_info "Système : $OS_NAME"

    check_dependencies

    # Création du dossier de résultats
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    local run_dir="${OUTPUT_DIR}/${DOMAIN}_${timestamp}"
    mkdir -p "$run_dir"
    log_success "Dossier de sortie : $run_dir"

    # Chemins des fichiers de sortie
    local raw_ct_file="${run_dir}/raw_ct_logs.json"
    local all_fqdns_file="${run_dir}/all_fqdns.txt"
    local wildcards_file="${run_dir}/wildcards.txt"
    local emails_file="${run_dir}/emails.txt"
    local dns_resolved_file="${run_dir}/dns_resolved.txt"
    local dns_unresolved_file="${run_dir}/dns_unresolved.txt"
    local ipv4_file="${run_dir}/ipv4_unique.txt"
    local ipv6_file="${run_dir}/ipv6_unique.txt"
    local summary_file="${run_dir}/summary.txt"

    # -------------------------------------------------------------------------
    echo ""
    echo "${BOLD}━━━ ÉTAPE 1/4 : Requête CT Logs ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    query_ct_logs "$DOMAIN" "$raw_ct_file"
    local cert_count
    cert_count=$(jq 'length' "$raw_ct_file")

    # -------------------------------------------------------------------------
    echo ""
    echo "${BOLD}━━━ ÉTAPE 2/4 : Extraction des FQDNs ━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    extract_fqdns "$raw_ct_file" "$all_fqdns_file" "$wildcards_file" "$emails_file"
    local fqdn_count wildcard_count email_count
    fqdn_count=$(wc -l < "$all_fqdns_file" | tr -d ' ')
    wildcard_count=0
    if [ -f "$wildcards_file" ]; then wildcard_count=$(wc -l < "$wildcards_file" | tr -d ' '); fi
    email_count=0
    if [ -f "$emails_file" ];    then email_count=$(wc    -l < "$emails_file"    | tr -d ' '); fi

    # -------------------------------------------------------------------------
    echo ""
    echo "${BOLD}━━━ ÉTAPE 3/4 : Vérification DNS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    local dns_stats
    dns_stats=$(verify_dns "$all_fqdns_file" "$dns_resolved_file" "$dns_unresolved_file")

    # Extraction des adresses IP uniques depuis dns_resolved.txt
    local ipv4_count=0 ipv6_count=0
    if [ -f "$dns_resolved_file" ]; then
        # Colonne A (IPv4) : champ 2 ; colonne AAAA (IPv6) : champ 3.
        # On filtre strictement pour ignorer "N/A", lignes vides, séparateurs.
        awk -F '|' -v re="$RE_IPV4" 'NR>5 { gsub(/^ +| +$/, "", $2); if ($2 ~ re) print $2 }' \
            "$dns_resolved_file" | sort -u > "$ipv4_file"
        awk -F '|' -v re="$RE_IPV6" 'NR>5 { gsub(/^ +| +$/, "", $3); if ($3 ~ re) print $3 }' \
            "$dns_resolved_file" | sort -u > "$ipv6_file"
        # Supprimer si vide
        if [ -s "$ipv4_file" ]; then
            ipv4_count=$(wc -l < "$ipv4_file" | tr -d ' ')
            log_success "${ipv4_count} adresses IPv4 uniques extraites"
        else
            rm -f "$ipv4_file"
        fi
        if [ -s "$ipv6_file" ]; then
            ipv6_count=$(wc -l < "$ipv6_file" | tr -d ' ')
            log_success "${ipv6_count} adresses IPv6 uniques extraites"
        else
            rm -f "$ipv6_file"
        fi
    fi

    # -------------------------------------------------------------------------
    echo ""
    echo "${BOLD}━━━ ÉTAPE 4/4 : Génération du rapport ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    generate_summary "$DOMAIN" "$run_dir" "$cert_count" "$fqdn_count" \
        "$wildcard_count" "$email_count" "$dns_stats" "$summary_file"

    # -------------------------------------------------------------------------
    echo ""
    echo "${BOLD}${GREEN}━━━ TERMINÉ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    cat "$summary_file"
    echo ""
    echo "${BLUE}Résultats complets dans :${NC} ${BOLD}${run_dir}/${NC}"
}

main "$@"
