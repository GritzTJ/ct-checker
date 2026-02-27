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
readonly SCRIPT_VERSION="1.0.0"
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
DNS_TOOL=""
OS_NAME="unknown"
PKG_MANAGER=""

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
    -v              Mode verbeux
    -h              Afficher cette aide

${BOLD}EXEMPLES:${NC}
    $0 -d example.com
    $0 -d example.com -o /tmp/resultats -v

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

    log_info "Extraction des FQDNs uniques depuis les données CT..."

    # name_value peut contenir plusieurs SANs séparés par \n
    # On extrait, on nettoie, on déduplique
    jq -r '.[].name_value' "$ct_file" \
        | tr ',' '\n' \
        | sed 's/^[[:space:]]*//' \
        | sed 's/[[:space:]]*$//' \
        | grep -v '^$' \
        | sort -u > /tmp/ct_all_names_$$.txt

    # Séparation : wildcards vs FQDNs normaux
    grep '^\*\.' /tmp/ct_all_names_$$.txt > "$wildcards_file" 2>/dev/null || true
    grep -v '^\*\.' /tmp/ct_all_names_$$.txt > "$fqdns_file" 2>/dev/null || true

    rm -f /tmp/ct_all_names_$$.txt

    local fqdn_count wildcard_count
    fqdn_count=$(wc -l < "$fqdns_file" | tr -d ' ')
    wildcard_count=$(wc -l < "$wildcards_file" | tr -d ' ')

    # Supprime le fichier wildcards s'il est vide
    [ "$wildcard_count" -eq 0 ] && rm -f "$wildcards_file"

    log_success "${fqdn_count} FQDNs uniques extraits"
    if [ "$wildcard_count" -gt 0 ]; then
        log_success "${wildcard_count} entrées wildcard isolées (stockées séparément)"
    else
        log_info "Aucun wildcard trouvé"
    fi
}

# ---------------------------------------------------------------------------
# Résolution DNS selon l'outil disponible
# ---------------------------------------------------------------------------

# Retourne les enregistrements DNS séparés par des virgules, ou chaîne vide
_resolve_dig() {
    local fqdn="$1" type="$2"
    dig +short +timeout=5 +tries=2 "$type" "$fqdn" 2>/dev/null \
        | grep -v '^;' | grep -v '^$' \
        | tr '\n' ',' | sed 's/,$//'
}

_resolve_nslookup() {
    local fqdn="$1" type="$2"
    nslookup -type="$type" -timeout=5 "$fqdn" 2>/dev/null \
        | grep -Ev '^(Server|Address|$|;)' \
        | awk '/^[^*]/ {print $NF}' \
        | tr '\n' ',' | sed 's/,$//'
}

_resolve_host() {
    local fqdn="$1" type="$2"
    host -t "$type" -W 5 "$fqdn" 2>/dev/null \
        | grep -iv 'nxdomain\|not found\|servfail\|timed out' \
        | awk '{print $NF}' \
        | tr '\n' ',' | sed 's/,$//'
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

        local line
        printf -v line "%-60s | %-35s | %-40s | %s" \
            "$fqdn" \
            "${a_recs:-N/A}" \
            "${aaaa_recs:-N/A}" \
            "${cname_rec:-N/A}"

        if [ "$is_resolved" = "true" ]; then
            resolved_count=$((resolved_count + 1))
            echo "$line" >> "$tmp_resolved"
        else
            unresolved_count=$((unresolved_count + 1))
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
    local dns_stats="$6"
    local summary_file="$7"

    local dns_total dns_resolved dns_unresolved
    IFS='|' read -r dns_total dns_resolved dns_unresolved <<< "$dns_stats"

    local resolution_rate="N/A"
    if [ "$dns_total" -gt 0 ] 2>/dev/null; then
        resolution_rate=$(awk "BEGIN {printf \"%.1f%%\", ($dns_resolved / $dns_total) * 100}")
    fi

    # Ligne wildcards conditionnelle
    local wildcard_line
    if [ "$wildcard_count" -gt 0 ]; then
        wildcard_line="  Wildcards      : ${wildcard_count} (stockés dans wildcards.txt, non vérifiés DNS)"
    else
        wildcard_line="  Wildcards      : Aucun"
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
    local _known_files=(raw_ct_logs.json all_fqdns.txt wildcards.txt dns_resolved.txt dns_unresolved.txt)
    for _f in "${_known_files[@]}"; do
        local _fp="${run_dir}/${_f}"
        if [ -f "$_fp" ]; then
            local _sz
            _sz=$(du -sh "$_fp" 2>/dev/null | cut -f1)
            printf -v _entry "  %-38s %s\n" "$_f" "$_sz"
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

  SOURCE CT LOGS
  --------------
  Fournisseur    : crt.sh (agrégateur de tous les CT logs publics)
  Logs couverts  : Google Argon/Xenon, DigiCert Yeti, Cloudflare Nimbus,
                   Sectigo, Let's Encrypt Oak, Trust Asia, etc.
  Certificats    : ${cert_count} entrées trouvées

================================================================================

  RÉSULTATS FQDNs
  ---------------
  FQDNs uniques  : ${fqdn_count} (wildcards exclus)
${wildcard_line}

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

    while getopts "d:o:vh" opt; do
        case $opt in
            d) DOMAIN="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
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
    rm -f /tmp/ct_check_*.json /tmp/ct_all_names_$$.txt 2>/dev/null || true
    printf "\r%80s\r" "" >&2
    log_warn "Interruption détectée. Fichiers temporaires nettoyés."
}
trap cleanup INT TERM

# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    # Dossier de sortie par défaut = nom du domaine si -o non fourni
    [ -z "$OUTPUT_DIR" ] && OUTPUT_DIR="./${DOMAIN}"

    local _border="═══════════════════════════════════════════════════════════════"
    local _title="Certificate Transparency Log Checker  v${SCRIPT_VERSION}"
    local _inner=${#_border}
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
    local dns_resolved_file="${run_dir}/dns_resolved.txt"
    local dns_unresolved_file="${run_dir}/dns_unresolved.txt"
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
    extract_fqdns "$raw_ct_file" "$all_fqdns_file" "$wildcards_file"
    local fqdn_count wildcard_count
    fqdn_count=$(wc -l < "$all_fqdns_file" | tr -d ' ')
    wildcard_count=0
    [ -f "$wildcards_file" ] && wildcard_count=$(wc -l < "$wildcards_file" | tr -d ' ')

    # -------------------------------------------------------------------------
    echo ""
    echo "${BOLD}━━━ ÉTAPE 3/4 : Vérification DNS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    local dns_stats
    dns_stats=$(verify_dns "$all_fqdns_file" "$dns_resolved_file" "$dns_unresolved_file")

    # -------------------------------------------------------------------------
    echo ""
    echo "${BOLD}━━━ ÉTAPE 4/4 : Génération du rapport ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    generate_summary "$DOMAIN" "$run_dir" "$cert_count" "$fqdn_count" \
        "$wildcard_count" "$dns_stats" "$summary_file"

    # -------------------------------------------------------------------------
    echo ""
    echo "${BOLD}${GREEN}━━━ TERMINÉ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    cat "$summary_file"
    echo ""
    echo "${BLUE}Résultats complets dans :${NC} ${BOLD}${run_dir}/${NC}"
}

main "$@"
