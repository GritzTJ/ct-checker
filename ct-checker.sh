#!/bin/bash
# =============================================================================
# ct-checker.sh - Certificate Transparency Log Checker
# =============================================================================
# Interroge les CT logs pour un domaine donné, extrait tous les FQDNs
# et vérifie leur résolution DNS. Compatible avec toutes les distros GNU/Linux.
#
# Usage: ./ct-checker.sh -d example.com [-o /chemin/resultats] [-v]
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Métadonnées
# ---------------------------------------------------------------------------
readonly SCRIPT_NAME="ct-checker.sh"
readonly SCRIPT_VERSION="1.0.3"
readonly CRT_SH_API="https://crt.sh"

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
OS_NAME="unknown"
PKG_MANAGER=""
_CLEANUP_FILES=()         # fichiers temporaires à supprimer en cas d'interruption

# ---------------------------------------------------------------------------
# Fonctions de log
# ---------------------------------------------------------------------------
log_info()    { echo "${BLUE}[*]${NC} $*"; }
log_success() { echo "${GREEN}[+]${NC} $*"; }
log_warn()    { echo "${YELLOW}[!]${NC} $*"; }
log_error()   { echo "${RED}[-]${NC} $*" >&2; }
log_debug()   { $VERBOSE && echo "${CYAN}[D]${NC} $*" || true; }

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
    -f              Afficher uniquement les FQDNs et wildcards (pas de fichiers)
    -4              Afficher uniquement les IPv4 uniques (pas de fichiers)
    -6              Afficher uniquement les IPv6 uniques (pas de fichiers)
    -v              Mode verbeux
    -h              Afficher cette aide

${BOLD}EXEMPLES:${NC}
    $0 -d example.com
    $0 -d example.com -o /tmp/resultats -v
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
    log_info "Vérification des dépendances..."

    local missing_tools=()
    local dns_tools=("dig" "nslookup" "host")

    for tool in curl jq; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done

    # Cherche le premier outil DNS disponible
    DNS_TOOL=""
    for tool in "${dns_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            DNS_TOOL="$tool"
            break
        fi
    done

    [ -z "$DNS_TOOL" ] && missing_tools+=("dig")

    if [ ${#missing_tools[@]} -eq 0 ]; then
        log_success "Dépendances OK (outil DNS : $DNS_TOOL)"
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

    # Réinitialise DNS_TOOL si dig vient d'être installé
    if [ -z "$DNS_TOOL" ] && command -v dig &>/dev/null; then
        DNS_TOOL="dig"
    fi

    log_success "Toutes les dépendances sont prêtes"
}

# ---------------------------------------------------------------------------
# Requête des CT logs via crt.sh
# ---------------------------------------------------------------------------
query_ct_logs() {
    local domain="$1"
    local output_file="$2"

    log_info "Interrogation des CT logs via crt.sh..."
    log_info "Agrège : Google, DigiCert, Cloudflare Nimbus, Sectigo, Let's Encrypt, etc."

    local tmp1 tmp2
    tmp1=$(mktemp /tmp/ct_check_XXXXXX.json)
    tmp2=$(mktemp /tmp/ct_check_XXXXXX.json)
    _CLEANUP_FILES+=("$tmp1" "$tmp2")

    # Requête 1 : sous-domaines (%.domain.com)
    log_debug "Requête 1 : sous-domaines (%.${domain})"
    local resp_code
    resp_code=$(curl -s -o "$tmp1" -w "%{http_code}" \
        --max-time 90 --retry 3 --retry-delay 5 --retry-max-time 120 \
        -H "Accept: application/json" \
        "${CRT_SH_API}/?q=%25.${domain}&output=json" 2>/dev/null) || true

    if [ "$resp_code" != "200" ]; then
        log_warn "crt.sh a retourné HTTP $resp_code pour la requête sous-domaines"
    fi

    # Requête 2 : domaine exact
    log_debug "Requête 2 : domaine exact (${domain})"
    curl -s -o "$tmp2" \
        --max-time 90 --retry 3 --retry-delay 5 --retry-max-time 120 \
        -H "Accept: application/json" \
        "${CRT_SH_API}/?q=${domain}&output=json" 2>/dev/null || true

    # Validation JSON et fusion
    local valid1=false valid2=false
    jq -e 'if type == "array" then . else error end' "$tmp1" &>/dev/null && valid1=true
    jq -e 'if type == "array" then . else error end' "$tmp2" &>/dev/null && valid2=true

    if ! $valid1 && ! $valid2; then
        log_error "Aucune réponse JSON valide depuis crt.sh. Vérifiez votre connexion internet."
        rm -f "$tmp1" "$tmp2"
        exit 1
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

    local count
    count=$(jq 'length' "$output_file")
    log_success "${count} entrées de certificats trouvées dans les CT logs"
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

    # name_value peut contenir plusieurs SANs séparés par \n
    # On extrait, on nettoie, on déduplique
    local tmp_names
    tmp_names=$(mktemp /tmp/ct_all_names_XXXXXX.txt)
    _CLEANUP_FILES+=("$tmp_names")

    jq -r '.[].name_value' "$ct_file" \
        | tr ',' '\n' \
        | sed 's/^[[:space:]]*//' \
        | sed 's/[[:space:]]*$//' \
        | grep -v '^$' \
        | sort -u > "$tmp_names"

    # Séparation en trois catégories :
    # 1. Adresses e-mail (contiennent @) — SANs de type rfc822Name
    grep '@' "$tmp_names" > "$emails_file" 2>/dev/null || true
    # 2. Wildcards (commencent par *.) — hors e-mails
    grep -v '@' "$tmp_names" | grep '^\*\.' > "$wildcards_file" 2>/dev/null || true
    # 3. FQDNs normaux — ni e-mail, ni wildcard
    grep -v '@' "$tmp_names" | grep -v '^\*\.' > "$fqdns_file" 2>/dev/null || true

    rm -f "$tmp_names"

    local fqdn_count wildcard_count email_count
    fqdn_count=$(wc -l < "$fqdns_file" | tr -d ' ')
    wildcard_count=$(wc -l < "$wildcards_file" | tr -d ' ')
    email_count=$(wc -l < "$emails_file" | tr -d ' ')

    # Supprime les fichiers vides
    [ "$wildcard_count" -eq 0 ] && rm -f "$wildcards_file"
    [ "$email_count" -eq 0 ] && rm -f "$emails_file"

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

# Retourne les enregistrements DNS séparés par des virgules, ou chaîne vide
_resolve_dig() {
    local fqdn="$1" type="$2"
    local raw
    raw=$(dig +short +timeout=5 +tries=2 "$type" "$fqdn" 2>/dev/null \
        | grep -v '^;' | grep -v '^$')
    # Pour A et AAAA, ne garder que les adresses IP (exclure les CNAME intermédiaires)
    case "$type" in
        A)    raw=$(echo "$raw" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') ;;
        AAAA) raw=$(echo "$raw" | grep -E '^[0-9a-fA-F:]+$') ;;
    esac
    echo "$raw" | grep -v '^$' | tr '\n' ',' | sed 's/,$//'
}

_resolve_nslookup() {
    local fqdn="$1" type="$2"
    local raw
    raw=$(nslookup -type="$type" -timeout=5 "$fqdn" 2>/dev/null \
        | grep -Ev '^(Server|Address|$|;)' \
        | awk '/^[^*]/ {print $NF}')
    case "$type" in
        A)    raw=$(echo "$raw" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') ;;
        AAAA) raw=$(echo "$raw" | grep -E '^[0-9a-fA-F:]+$') ;;
    esac
    echo "$raw" | grep -v '^$' | tr '\n' ',' | sed 's/,$//'
}

_resolve_host() {
    local fqdn="$1" type="$2"
    local raw
    raw=$(host -t "$type" -W 5 "$fqdn" 2>/dev/null \
        | grep -iv 'nxdomain\|not found\|servfail\|timed out' \
        | awk '{print $NF}')
    case "$type" in
        A)    raw=$(echo "$raw" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') ;;
        AAAA) raw=$(echo "$raw" | grep -E '^[0-9a-fA-F:]+$') ;;
    esac
    echo "$raw" | grep -v '^$' | tr '\n' ',' | sed 's/,$//'
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
    { [ -n "$a_records" ] || [ -n "$aaaa_records" ] || [ -n "$cname_record" ]; } && resolved=true

    echo "${resolved}|${a_records}|${aaaa_records}|${cname_record}"
}

# ---------------------------------------------------------------------------
# Boucle principale de vérification DNS
# ---------------------------------------------------------------------------
verify_dns() {
    local fqdns_file="$1"
    local resolved_file="$2"
    local unresolved_file="$3"

    local total
    total=$(grep -c . "$fqdns_file" 2>/dev/null || echo 0)
    local resolved_count=0
    local unresolved_count=0

    log_info "Vérification DNS de ${total} FQDNs (outil : ${DNS_TOOL})..." >&2

    # Fichiers temporaires pour collecter les données avant d'écrire les fichiers finaux
    local tmp_resolved tmp_unresolved
    tmp_resolved=$(mktemp /tmp/ct_dns_res_XXXXXX.txt)
    tmp_unresolved=$(mktemp /tmp/ct_dns_nores_XXXXXX.txt)
    _CLEANUP_FILES+=("$tmp_resolved" "$tmp_unresolved")

    local current=0
    while IFS= read -r fqdn; do
        [ -z "$fqdn" ] && continue
        current=$((current + 1))

        # Indicateur de progression sur stderr
        printf "\r  [%d/%d] Vérification : %-50s" "$current" "$total" "$fqdn" >&2

        local result
        result=$(check_dns "$fqdn")

        local is_resolved a_recs aaaa_recs cname_rec
        IFS='|' read -r is_resolved a_recs aaaa_recs cname_rec <<< "$result"

        # --- Construire les lignes (multi-ligne si plusieurs IPs) ---
        local -a a_arr=() aaaa_arr=()
        [ -n "$a_recs" ] && IFS=',' read -ra a_arr <<< "$a_recs"
        [ -n "$aaaa_recs" ] && IFS=',' read -ra aaaa_arr <<< "$aaaa_recs"

        local max_lines=${#a_arr[@]}
        [ ${#aaaa_arr[@]} -gt "$max_lines" ] && max_lines=${#aaaa_arr[@]}
        [ "$max_lines" -eq 0 ] && max_lines=1

        local line
        if [ "$is_resolved" = "true" ]; then
            resolved_count=$((resolved_count + 1))
            # Première ligne : FQDN + première IP de chaque type + CNAME
            printf -v line "%-60s | %-35s | %-40s | %s" \
                "$fqdn" \
                "${a_arr[0]:-N/A}" \
                "${aaaa_arr[0]:-N/A}" \
                "${cname_rec:-N/A}"
            echo "$line" >> "$tmp_resolved"
            # Lignes suivantes : IPs supplémentaires (colonnes FQDN et CNAME vides)
            local i
            for ((i=1; i<max_lines; i++)); do
                printf -v line "%-60s | %-35s | %-40s |" \
                    "" \
                    "${a_arr[$i]:-}" \
                    "${aaaa_arr[$i]:-}"
                echo "$line" >> "$tmp_resolved"
            done
            # Séparateur horizontal si le FQDN avait plusieurs lignes
            if [ "$max_lines" -gt 1 ]; then
                printf '%0.s-' {1..155} >> "$tmp_resolved"
                echo "" >> "$tmp_resolved"
            fi
        else
            unresolved_count=$((unresolved_count + 1))
            printf -v line "%-60s | %-35s | %-40s | %s" \
                "$fqdn" "N/A" "N/A" "N/A"
            echo "$line" >> "$tmp_unresolved"
        fi

    done < "$fqdns_file"

    # Efface la ligne de progression
    printf "\r%80s\r" "" >&2

    # En-tête commun pour les fichiers de résultats
    local header separator
    header=$(printf "%-60s | %-35s | %-40s | %s" "FQDN" "A (IPv4)" "AAAA (IPv6)" "CNAME")
    separator=$(printf '%0.s-' {1..155})

    # N'écrit les fichiers finaux que s'ils contiennent des données
    if [ "$resolved_count" -gt 0 ]; then
        {
            echo "# DNS Verification Results (RESOLVED) - $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
            echo "# Domaine : $DOMAIN | Outil DNS : $DNS_TOOL"
            echo "$separator"
            echo "$header"
            echo "$separator"
            cat "$tmp_resolved"
        } > "$resolved_file"
    fi

    if [ "$unresolved_count" -gt 0 ]; then
        {
            echo "# DNS Verification Results (UNRESOLVED) - $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
            echo "# Domaine : $DOMAIN | Outil DNS : $DNS_TOOL"
            echo "$separator"
            echo "$header"
            echo "$separator"
            cat "$tmp_unresolved"
        } > "$unresolved_file"
    fi

    rm -f "$tmp_resolved" "$tmp_unresolved"

    log_success "DNS : ${resolved_count} résolus, ${unresolved_count} non résolus (sur ${total})" >&2

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
  Date           : $(date '+%Y-%m-%d %H:%M:%S')
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

    while getopts "d:o:f46vh" opt; do
        case $opt in
            d) DOMAIN="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            f) STDOUT_MODE="f" ;;
            4) STDOUT_MODE="4" ;;
            6) STDOUT_MODE="6" ;;
            v) VERBOSE=true ;;
            h) usage ;;
            *) usage ;;
        esac
    done

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
    [ ${#_CLEANUP_FILES[@]} -gt 0 ] && rm -f "${_CLEANUP_FILES[@]}" 2>/dev/null || true
    _CLEANUP_FILES=()
    printf "\r%80s\r" "" >&2
    log_warn "Interruption détectée. Fichiers temporaires nettoyés."
}
trap cleanup INT TERM

# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    # --- Mode stdout (-f / -4 / -6) : tout dans un tmpdir, affichage sur stdout ---
    if [ -n "$STDOUT_MODE" ]; then
        STDOUT_TMPDIR=$(mktemp -d /tmp/ct_checker_XXXXXX)
        trap 'rm -rf "$STDOUT_TMPDIR"' EXIT
        local tmpdir="$STDOUT_TMPDIR"

        detect_os
        check_dependencies

        log_info "Domaine cible : ${BOLD}${DOMAIN}${NC}" >&2
        case "$STDOUT_MODE" in
            f) log_info "Mode : FQDNs et wildcards uniquement (pas de fichiers sur disque)" >&2 ;;
            *) log_info "Mode : IPv${STDOUT_MODE} uniquement (pas de fichiers sur disque)" >&2 ;;
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
            [ -f "$all_fqdns_file" ] && cat "$all_fqdns_file"
            [ -f "$wildcards_file" ] && cat "$wildcards_file"
            return 0
        fi

        local fqdn_count
        fqdn_count=$(wc -l < "$all_fqdns_file" | tr -d ' ')
        log_info "${fqdn_count} FQDNs à vérifier" >&2

        # Étape 3 : vérification DNS
        local dns_resolved_file="${tmpdir}/dns_resolved.txt"
        verify_dns "$all_fqdns_file" "$dns_resolved_file" "${tmpdir}/dns_unresolved.txt" > /dev/null

        # Étape 4 : extraction et affichage des IPs
        if [ -f "$dns_resolved_file" ]; then
            if [ "$STDOUT_MODE" = "4" ]; then
                awk -F '|' 'NR>5 { gsub(/^ +| +$/, "", $2); if ($2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $2 }' \
                    "$dns_resolved_file" | sort -u
            else
                awk -F '|' 'NR>5 { gsub(/^ +| +$/, "", $3); if ($3 ~ /^[0-9a-fA-F:]+$/) print $3 }' \
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
    [ -f "$wildcards_file" ] && wildcard_count=$(wc -l < "$wildcards_file" | tr -d ' ')
    email_count=0
    [ -f "$emails_file" ] && email_count=$(wc -l < "$emails_file" | tr -d ' ')

    # -------------------------------------------------------------------------
    echo ""
    echo "${BOLD}━━━ ÉTAPE 3/4 : Vérification DNS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    local dns_stats
    dns_stats=$(verify_dns "$all_fqdns_file" "$dns_resolved_file" "$dns_unresolved_file")

    # Extraction des adresses IP uniques depuis dns_resolved.txt
    local ipv4_count=0 ipv6_count=0
    if [ -f "$dns_resolved_file" ]; then
        # Colonne A (IPv4) : champ 2 après le premier |
        # Colonne AAAA (IPv6) : champ 3 après le deuxième |
        awk -F '|' 'NR>5 { gsub(/^ +| +$/, "", $2); if ($2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $2 }' \
            "$dns_resolved_file" | sort -u > "$ipv4_file"
        awk -F '|' 'NR>5 { gsub(/^ +| +$/, "", $3); if ($3 ~ /^[0-9a-fA-F:]+$/) print $3 }' \
            "$dns_resolved_file" | sort -u > "$ipv6_file"
        # Supprimer si vide
        [ -s "$ipv4_file" ] && ipv4_count=$(wc -l < "$ipv4_file" | tr -d ' ') || rm -f "$ipv4_file"
        [ -s "$ipv6_file" ] && ipv6_count=$(wc -l < "$ipv6_file" | tr -d ' ') || rm -f "$ipv6_file"
        [ "$ipv4_count" -gt 0 ] && log_success "${ipv4_count} adresses IPv4 uniques extraites"
        [ "$ipv6_count" -gt 0 ] && log_success "${ipv6_count} adresses IPv6 uniques extraites"
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
