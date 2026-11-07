#!/usr/bin/env bash
#
# Usage : sudo ./ban-path-explorer.sh [options]     (root obligatoire, sauf --help)
# Exemples :
#   sudo ./ban-path-explorer.sh                              # analyse sans bannir (dry-run)
#   sudo ./ban-path-explorer.sh --history                    # enquête sur tout l'historique lu
#   sudo ./ban-path-explorer.sh --threshold 25 --window 20
#   sudo ./ban-path-explorer.sh --log-files "error.log site-error.log" --ignore-paths "favicon.ico,robots.txt"
#   sudo ./ban-path-explorer.sh --ban                        # bannit
#   sudo ./ban-path-explorer.sh --follow --ban --quiet       # surveillance continue (cf. service systemd)
#
# Whitelist : /etc/ban-path-explorer/safe-ips.txt (IPs, plages CIDR, # commentaires).
# Modèle : scripts/safe-ips.example.txt

set -u

VERSION="2.0"
REQUIRE_ROOT="1"   # mis à 0 uniquement par le script de test (copie isolée)
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAFE_IPS_FILE="/etc/ban-path-explorer/safe-ips.txt"   # hors du repo : vos IPs ne sont pas publiées
REPO_SAFE_IPS_FILE="$SCRIPT_DIR/safe-ips.txt"          # ancien emplacement, migré automatiquement
BAD_PATTERNS_FILE="$SCRIPT_DIR/bad-patterns.txt"
TRACK_LOG="/var/log/ban-path-explorer.log"
BAN_STATE_FILE="/var/lib/ban-path-explorer/state"
LEGACY_BAN_STATE_FILE="/var/log/ban-path-explorer.state"
LOCK_DIR_BASE="/run/ban-path-explorer.lock"   # /run : écriture root uniquement (pas /tmp)

DEFAULT_LOG_DIR="/var/log/apache2"
DEFAULT_THRESHOLD="20"
DEFAULT_WINDOW_MINUTES="30"
DEFAULT_BAN_DURATION_MINUTES="60"
# ponytail: paliers de récidive fixes (minutes) ; en faire des options si besoin réel
RECIDIVE_MINUTES=(0 1440 10080 43200)   # 2e ban : 24 h, 3e : 7 j, 4e et + : 30 j
RECIDIVE_MEMORY_SECONDS=$((30 * 86400))   # un ban expiré est retenu 30 j pour compter les récidives
DEFAULT_IGNORE_PATHS=""
DEFAULT_QUIET="0"
DEFAULT_BAN="0"
DEFAULT_MAX_LOG_LINES="20000"
DEFAULT_MAX_EVENTS="200000"
DEFAULT_FOLLOW="0"
DEFAULT_FOLLOW_INTERVAL_SECONDS="5"

LOG_DIR="$DEFAULT_LOG_DIR"
LOG_FILES_RAW=""
THRESHOLD="$DEFAULT_THRESHOLD"
WINDOW_MINUTES="$DEFAULT_WINDOW_MINUTES"
BAN_DURATION_MINUTES="$DEFAULT_BAN_DURATION_MINUTES"
IGNORE_PATHS_RAW="$DEFAULT_IGNORE_PATHS"
QUIET="$DEFAULT_QUIET"
BAN_ENABLED="$DEFAULT_BAN"
MAX_LOG_LINES="$DEFAULT_MAX_LOG_LINES"
MAX_EVENTS="$DEFAULT_MAX_EVENTS"
LOCK_DIR="$LOCK_DIR_BASE"
FOLLOW_MODE="$DEFAULT_FOLLOW"
FOLLOW_INTERVAL_SECONDS="$DEFAULT_FOLLOW_INTERVAL_SECONDS"

WINDOW_SECONDS="0"
BAN_DURATION_SECONDS="0"

declare -a LOG_FILES=()
declare -a IGNORE_PATHS=()
declare -A SAFE_IPS=()
declare -a SAFE_CIDRS=()
declare -A SAFE_CACHE=()
declare -A BEST_COUNT=()
declare -A BEST_START=()
declare -A BEST_END=()
declare -A BEST_PATHS=()
declare -A BEST_TOTAL_EVENTS=()
declare -A SIG_HIT=()
declare -A LAST_TS=()
declare -A ST_EXP=()
declare -A ST_COUNT=()
declare -A ST_SINCE=()
NOW_TS="$(date '+%s')"
BAN_UNTIL=""
BAN_COUNT="0"
HISTORY_MODE="0"
RUNNING_PID=""
WORK_DIR=""

print_usage() {
  cat <<EOF
Usage: sudo ./$SCRIPT_NAME [options]

Sans --ban, le script analyse et affiche les IPs suspectes sans rien bloquer (dry-run).
Surveillance permanente : installer scripts/ban-path-explorer.service (voir README)

Options:
  --log-dir DIR            Dossier des logs Apache (défaut: $DEFAULT_LOG_DIR)
  --log-files "F1 F2 ..."  Liste de fichiers logs séparés par des espaces
                           (défaut: *error*.log, *access*.log, *error_log, *access_log de --log-dir)
  --threshold N            Seuil d'URLs différentes par IP (défaut: $DEFAULT_THRESHOLD)
  --window MIN             Fenêtre glissante en minutes (défaut: $DEFAULT_WINDOW_MINUTES)
  --max-log-lines N        Max lignes lues par fichier log (défaut: $DEFAULT_MAX_LOG_LINES)
  --max-events N           Max événements traités par exécution (défaut: $DEFAULT_MAX_EVENTS)
  --follow                 Mode continu: relance l'analyse en boucle
  --follow-interval SEC    Intervalle en secondes en mode --follow (défaut: $DEFAULT_FOLLOW_INTERVAL_SECONDS)
  --lock-dir DIR           Verrou d'exécution unique (défaut: $LOCK_DIR_BASE)
  --ignore-paths "a,b,c"   Ignore les chemins contenant ces motifs
  --ban                    Active le blocage IPTables
  --ban-duration MIN       Durée du 1er blocage en minutes (défaut: $DEFAULT_BAN_DURATION_MINUTES)
                           Récidive (mémoire 30 j) : 2e ban 24 h, 3e 7 j, puis 30 j
  --history                Analyse tout l'historique lu (par défaut : seulement
                           les événements des --window dernières minutes)
  --quiet                  N'affiche rien à l'écran
  --help                   Affiche cette aide
EOF
}

early_help_return() {
  local arg
  for arg in "$@"; do
    case "$arg" in
      --help|-h)
        print_usage
        return 0
        ;;
    esac
  done
  return 1
}

is_uint() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

# Accepte uniquement une IPv4/IPv6 unique (jamais de CIDR, de nom d'hôte ni d'adresse "tout le monde").
is_valid_ip() {
  local ip="$1" o
  case "$ip" in
    ''|*/*) return 1 ;;
    *:*)
      [[ $ip =~ ^[0-9A-Fa-f:]+$ ]] || return 1
      [ "$ip" != "::" ] && [ "$ip" != "::1" ]
      return
      ;;
  esac
  [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do
    [ "$((10#$o))" -le 255 ] || return 1
  done
  case "$ip" in
    0.*|127.*|255.255.255.255) return 1 ;;
  esac
  return 0
}

# Adresses privées : derrière un reverse proxy/load balancer, c'est l'IP du proxy qui apparaît
# dans les logs ; la bannir couperait tout le site. Le vrai client s'obtient via mod_remoteip.
is_private_ip() {
  local ip
  ip="$(printf '%s' "$1" | tr 'A-F' 'a-f')"
  case "$ip" in
    10.*|192.168.*|169.254.*|fc*|fd*|fe8*|fe9*|fea*|feb*) return 0 ;;
    172.*)
      local b="${ip#172.}"; b="${b%%.*}"
      [ "$b" -ge 16 ] && [ "$b" -le 31 ] ;;
    100.*)
      local b="${ip#100.}"; b="${b%%.*}"
      [ "$b" -ge 64 ] && [ "$b" -le 127 ] ;;
    *) return 1 ;;
  esac
}

# Toutes les adresses locales du serveur (v4 + v6) : jamais bannies, même absentes de safe-ips.txt.
load_local_ips() {
  local addr
  while read -r addr; do
    [ -n "$addr" ] && SAFE_IPS["$addr"]=1
  done < <(ip -o addr show 2>/dev/null | awk '{ split($4, a, "/"); print a[1] }')
}

# ipt IP args... : iptables pour une IPv4, ip6tables pour une IPv6
ipt() {
  case "$1" in
    *:*) shift; ip6tables -w "$@" ;;
    *) shift; iptables -w "$@" ;;
  esac
}

trim_spaces() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

say() {
  if [ "$QUIET" -eq 0 ]; then
    printf '%s\n' "$1"
  fi
}

log_track() {
  local now_line msg
  now_line="$(date '+%Y-%m-%d %H:%M:%S')"
  msg="$1"
  printf '[%s] %s\n' "$now_line" "$msg" >> "$TRACK_LOG"
}

# Lignes de routine (démarrage, fin...) : omises dans les cycles --follow pour ne pas
# écrire plusieurs lignes toutes les 5 secondes quand il ne se passe rien.
log_routine() {
  [ "${BAN_PATH_FOLLOW_CHILD:-0}" = "1" ] || log_track "$1"
}

setup_tracking_files() {
  local track_dir state_dir
  track_dir="$(dirname "$TRACK_LOG")"
  state_dir="$(dirname "$BAN_STATE_FILE")"
  if [ ! -d "$track_dir" ]; then
    mkdir -p "$track_dir" 2>/dev/null || return 1
  fi
  if [ ! -d "$state_dir" ]; then
    mkdir -p -m 700 "$state_dir" 2>/dev/null || return 1
  fi
  # Migration de l'ancien emplacement (un état n'est pas un log : logrotate pourrait le tronquer)
  if [ ! -s "$BAN_STATE_FILE" ] && [ -s "$LEGACY_BAN_STATE_FILE" ]; then
    cat "$LEGACY_BAN_STATE_FILE" > "$BAN_STATE_FILE" && rm -f "$LEGACY_BAN_STATE_FILE"
  fi
  touch "$TRACK_LOG" 2>/dev/null || return 1
  touch "$BAN_STATE_FILE" 2>/dev/null || return 1
  return 0
}

ensure_safe_ips_file() {
  [ -f "$SAFE_IPS_FILE" ] && return 0
  mkdir -p -m 700 "$(dirname "$SAFE_IPS_FILE")" 2>/dev/null || return 1
  if [ -f "$REPO_SAFE_IPS_FILE" ]; then
    install -m 600 "$REPO_SAFE_IPS_FILE" "$SAFE_IPS_FILE" || return 1
    log_track "Whitelist migrée: $REPO_SAFE_IPS_FILE -> $SAFE_IPS_FILE (vous pouvez supprimer l'ancien fichier)"
  else
    printf '127.0.0.1\n::1\n' > "$SAFE_IPS_FILE" && chmod 600 "$SAFE_IPS_FILE" || return 1
    log_track "Avertissement: whitelist absente, $SAFE_IPS_FILE créé vide (ajoutez vos IPs d'administration)"
    printf 'Avertissement: whitelist créée vide dans %s, ajoutez vos IPs d administration\n' "$SAFE_IPS_FILE" >&2
  fi
  return 0
}

# IPv6 -> 32 caractères hexadécimaux (développe "::")
ip6_hex() {
  local ip="$1" head tail g i n out=""
  local -a h=() t=()
  if [[ $ip == *::* ]]; then head="${ip%%::*}"; tail="${ip#*::}"; else head="$ip"; tail=""; fi
  [ -n "$head" ] && IFS=: read -ra h <<< "$head"
  [ -n "$tail" ] && IFS=: read -ra t <<< "$tail"
  n=$((8 - ${#h[@]} - ${#t[@]}))
  for g in "${h[@]}"; do out+="$(printf '%04x' "0x$g")"; done
  for ((i = 0; i < n; i++)); do out+="0000"; done
  for g in "${t[@]}"; do out+="$(printf '%04x' "0x$g")"; done
  printf '%s' "$out"
}

ip4_int() {
  local IFS=.
  local -a o=($1)
  printf '%s' "$(( (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3] ))"
}

# ip_in_cidr IP RESEAU/PREFIXE
ip_in_cidr() {
  local ip="$1" net="${2%/*}" bits="${2#*/}" a b full rem
  case "$ip" in
    *:*)
      [[ $net == *:* ]] || return 1
      a="$(ip6_hex "$ip")"; b="$(ip6_hex "$net")"
      full=$((bits / 4)); rem=$((bits % 4))
      [ "${a:0:full}" = "${b:0:full}" ] || return 1
      [ "$rem" -eq 0 ] && return 0
      [ $(( (0x${a:full:1} ^ 0x${b:full:1}) >> (4 - rem) )) -eq 0 ]
      ;;
    *)
      [[ $net == *:* ]] && return 1
      [ "$bits" -eq 0 ] && return 0
      [ $(( ( $(ip4_int "$ip") ^ $(ip4_int "$net") ) >> (32 - bits) )) -eq 0 ]
      ;;
  esac
}

# Whitelist : IP exacte, plage CIDR, ou adresse locale du serveur
is_safe_ip() {
  local ip="$1" c
  [ -n "${SAFE_IPS[$ip]+x}" ] && return 0
  [ "${#SAFE_CIDRS[@]}" -eq 0 ] && return 1
  if [ -z "${SAFE_CACHE[$ip]+x}" ]; then
    SAFE_CACHE["$ip"]=1
    for c in "${SAFE_CIDRS[@]}"; do
      if ip_in_cidr "$ip" "$c"; then SAFE_CACHE["$ip"]=0; break; fi
    done
  fi
  [ "${SAFE_CACHE[$ip]}" -eq 0 ]
}

load_safe_ips() {
  local ip_line cleaned
  while IFS= read -r ip_line || [ -n "$ip_line" ]; do
    cleaned="$(trim_spaces "${ip_line%%#*}")"
    [ -z "$cleaned" ] && continue
    case "$cleaned" in
      */*)
        if is_uint "${cleaned#*/}"; then
          SAFE_CIDRS+=("$cleaned")
        else
          log_track "Whitelist: plage ignorée (invalide): $cleaned"
        fi
        ;;
      *) SAFE_IPS["$cleaned"]=1 ;;
    esac
  done < "$SAFE_IPS_FILE"
}

parse_ignore_paths() {
  local oldifs token cleaned
  [ -z "$IGNORE_PATHS_RAW" ] && return 0
  oldifs="$IFS"
  IFS=','
  for token in $IGNORE_PATHS_RAW; do
    cleaned="$(trim_spaces "$token")"
    [ -n "$cleaned" ] && IGNORE_PATHS+=("$cleaned")
  done
  IFS="$oldifs"
}

should_ignore_path() {
  local path="$1"
  local token
  for token in "${IGNORE_PATHS[@]}"; do
    case "$path" in
      *"$token"*) return 0 ;;
    esac
  done
  return 1
}

build_log_files_list() {
  local f
  if [ -n "$LOG_FILES_RAW" ]; then
    for f in $LOG_FILES_RAW; do
      if [ "${f#/}" = "$f" ]; then
        f="$LOG_DIR/$f"
      fi
      if [ -f "$f" ]; then
        LOG_FILES+=("$f")
      else
        log_track "Fichier ignoré (inexistant): $f"
      fi
    done
  else
    # Debian : error.log, monsite-error.log, other_vhosts_access.log ; RHEL : error_log, ssl_access_log
    for f in "$LOG_DIR"/*error*.log "$LOG_DIR"/*access*.log "$LOG_DIR"/*error_log "$LOG_DIR"/*access_log; do
      [ -f "$f" ] || continue
      LOG_FILES+=("$f")
    done
  fi
}

# Avertit si un ErrorLog/CustomLog déclaré dans la config Apache n'est pas analysé
warn_uncovered_logs() {
  local f g covered
  [ -n "$LOG_FILES_RAW" ] && return 0
  while read -r f; do
    f="${f//\"/}"
    f="${f//\$\{APACHE_LOG_DIR\}/$LOG_DIR}"
    case "$f" in /*) ;; *) continue ;; esac   # pipe (|rotatelogs), syslog:, chemin relatif
    [ -f "$f" ] || continue
    covered=0
    for g in "${LOG_FILES[@]}"; do
      [ "$g" = "$f" ] && { covered=1; break; }
    done
    if [ "$covered" -eq 0 ]; then
      log_track "Avertissement: log Apache non analysé: $f (ajoutez-le avec --log-files ou --log-dir)"
      say "Avertissement : log Apache non analysé : $f"
    fi
  done < <(grep -RhoiE '^[[:space:]]*(ErrorLog|CustomLog)[[:space:]]+[^[:space:]]+' \
             /etc/apache2/apache2.conf /etc/apache2/sites-enabled /etc/apache2/conf-enabled \
             /etc/httpd/conf /etc/httpd/conf.d 2>/dev/null | awk '{ print $2 }' | sort -u)
}

parse_logs_to_tmp() {
  local out_file="$1"
  local f cutoff=0
  [ "$HISTORY_MODE" -eq 1 ] || cutoff=$((NOW_TS - WINDOW_SECONDS))
  : > "$out_file"
  for f in "${LOG_FILES[@]}"; do
    # tail lit depuis la fin du fichier : coût indépendant de la taille du log
    tail -n "$MAX_LOG_LINES" "$f" | awk -v max="$MAX_LOG_LINES" -v pf="$BAD_PATTERNS_FILE" -v fname="$f" \
      -v cutoff="$cutoff" -v tzoff="$(date '+%z')" '
      BEGIN {
        split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", mn, " ")
        for (k = 1; k <= 12; k++) MON[mn[k]] = k
        # Signatures à ban immédiat (sous-chaînes, insensibles à la casse)
        np = 0
        while ((getline p < pf) > 0) {
          sub(/[[:space:]]+$/, "", p)
          if (p == "" || substr(p, 1, 1) == "#") continue
          pat[++np] = tolower(p)
        }
      }
      # Jours depuis 1970-01-01 (algorithme "days from civil", sans appel à date)
      function days(y, m, d,   era, yoe, doy, doe) {
        y -= (m <= 2)
        era = int((y >= 0 ? y : y - 399) / 400)
        yoe = y - era * 400
        doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
        doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
        return era * 146097 + doe - 719468
      }
      # "06/Apr/2026:18:07:29 +0000" (access) ou "Mon Apr 06 18:07:29.239286 2026" (error, heure locale)
      # ponytail: heure locale convertie avec le décalage actuel ; faux d une heure autour d un changement d heure
      function to_epoch(t,   a, n, y, m, d, H, M, S, off) {
        if (t ~ /^[0-9][0-9]\/[A-Za-z][A-Za-z][A-Za-z]\/[0-9][0-9][0-9][0-9]:/) {
          d = substr(t, 1, 2) + 0; m = MON[substr(t, 4, 3)]; y = substr(t, 8, 4) + 0
          H = substr(t, 13, 2) + 0; M = substr(t, 16, 2) + 0; S = substr(t, 19, 2) + 0
          off = substr(t, 22, 5)
        } else {
          n = split(t, a, " ")
          m = MON[a[2]]; d = a[3] + 0; y = a[n] + 0
          H = substr(a[4], 1, 2) + 0; M = substr(a[4], 4, 2) + 0; S = substr(a[4], 7, 2) + 0
          off = tzoff
        }
        if (!m || !y) return -1
        if (off !~ /^[+-][0-9][0-9][0-9][0-9]$/) off = tzoff
        return days(y, m, d) * 86400 + H * 3600 + M * 60 + S \
          - (substr(off, 1, 1) == "-" ? -1 : 1) * (substr(off, 2, 2) * 3600 + substr(off, 4, 2) * 60)
      }
      # Écrit un événement : horodatage converti, et filtré sur la fenêtre (cutoff=0 avec --history)
      function emit(t, rest,   e) {
        e = to_epoch(t)
        if (e >= 0 && e >= cutoff) print e "\t" rest
      }
      function sig(s,   k) {
        s = tolower(s)
        for (k = 1; k <= np; k++) if (index(s, pat[k]) > 0) return pat[k]
        return ""
      }
      {
        buf[NR % max] = $0
      }
      END {
        start = (NR > max) ? NR - max + 1 : 1
        i = start
        while (i <= NR) {
          line = buf[i % max]
          # Access log (format common/combined, ou other_vhosts "vhost:port IP ...")
          if (substr(line, 1, 1) != "[") {
            split(line, f, " ")
            ip = f[1]
            if (ip ~ /:[0-9]+$/ && f[2] ~ /^[0-9A-Fa-f.:]+$/) ip = f[2]
            sub(/^::[fF][fF][fF][fF]:/, "", ip)
            lb = index(line, "[")
            rb = index(line, "]")
            q = index(line, "\"")
            if (lb == 0 || rb <= lb || q <= rb) { i++; continue }
            ts = substr(line, lb + 1, rb - lb - 1)
            rest = substr(line, q + 1)
            # fin de la requête = guillemet non échappé suivi du code HTTP
            if (!match(rest, /[^\\]" [0-9][0-9][0-9] /)) { i++; continue }
            req = substr(rest, 1, RSTART)
            status = substr(rest, RSTART + 3, 3)
            split(req, r, " ")
            url = r[2]
            sub(/\?.*/, "", url)
            if (url == "") { i++; continue }
            # requête + statut + referer + user-agent : Log4Shell/Shellshock passent par les en-têtes
            hit = sig(rest)
            if (hit != "") {
              emit(ts, ip "\t" url "\t" fname "\tsig:" hit)
            } else if (status ~ /^(400|403|404|405)$/) {
              emit(ts, ip "\t" url "\t" fname)
            } else if (r[1] == "POST" && url ~ /(wp-login|xmlrpc)\.php$/) {
              # ponytail: brute force = N POST distincts (le compteur porte sur les chemins uniques)
              emit(ts, ip "\tPOST " url " #" i "\t" fname)
            }
            i++
            continue
          }
          if (line ~ /\[[^]]*error\]/ &&
              (line ~ /File does not exist: / ||
               line ~ /AH01276:/ ||
               line ~ /ModSecurity: Access denied/ ||
               line ~ /script .* not found or unable to stat/)) {
            ts=""
            ip=""
            path=""
            marker=""
            quote=sprintf("%c", 39)

            if (line ~ /^\[[0-9][0-9]\/[A-Za-z][A-Za-z][A-Za-z]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9] [+-][0-9][0-9][0-9][0-9]\]/) {
              ts=substr(line, 2, 26)
            } else if (match(line, /^\[[A-Za-z][A-Za-z][A-Za-z] [A-Za-z][A-Za-z][A-Za-z] [ 0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9](\.[0-9]+)? [0-9][0-9][0-9][0-9]\]/)) {
              ts=substr(line, 2, RLENGTH - 2)
            } else {
              i++
              continue
            }
            client_pos=index(line, "[client ")
            if (client_pos > 0) {
              client_part=substr(line, client_pos + 8)
              client_end=index(client_part, "]")
              if (client_end > 1) {
                ip=substr(client_part, 1, client_end - 1)
                split(ip, ipa, " ")
                ip=ipa[1]
                # IPv4 mappée en IPv6 (::ffff:1.2.3.4) : le paquet arrive en IPv4, on banne en IPv4
                sub(/^::[fF][fF][fF][fF]:/, "", ip)
                if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/) {
                  sub(/:[0-9]+$/, "", ip)
                } else if (ip ~ /^[0-9A-Fa-f:]+:[0-9]+$/ && index(line, "[pid ") > 0) {
                  # ponytail: Apache 2.4 écrit "[client 2001:db8::1:54321]" (IPv6 + port, sans crochets) ;
                  # on retire le dernier segment. Format ErrorLogFormat personnalisé sans port = adresse fausse.
                  sub(/:[0-9]+$/, "", ip)
                } else if (ip ~ /^\[[0-9A-Fa-f:]+\]:[0-9]+$/) {
                  sub(/^\[/, "", ip)
                  sub(/\]:[0-9]+$/, "", ip)
                } else if (ip ~ /^\[[0-9A-Fa-f:]+\]$/) {
                  sub(/^\[/, "", ip)
                  sub(/\]$/, "", ip)
                }
              } else {
                i++
                continue
              }
            } else {
              i++
              continue
            }
            pos=index(line, "File does not exist: ")
            modsec = 0
            if (index(line, "ModSecurity: Access denied") > 0) {
              # Requête bloquée par le WAF : chemin dans [uri "..."], ban immédiat
              modsec = 1
              path = "/"
              u = index(line, "[uri \"")
              if (u > 0) {
                path = substr(line, u + 6)
                path = substr(path, 1, index(path, "\"") - 1)
              }
            } else if (pos > 0) {
              path=substr(line, pos + length("File does not exist: "))
            } else {
              pos2=index(line, "AH01276:")
              if (pos2 > 0) {
                path=substr(line, pos2 + length("AH01276:"))
                sub(/^[[:space:]]+/, "", path)
              } else {
                pos3=index(line, "script ")
                marker=" not found or unable to stat"
                if (pos3 > 0 && index(line, marker) > pos3) {
                  path=substr(line, pos3 + length("script "), index(line, marker) - (pos3 + length("script ")))
                  sub("^" quote, "", path)
                  sub(quote "$", "", path)
                } else {
                  i++
                  continue
                }
              }
            }
            hit = modsec ? "modsecurity" : sig(path)
            emit(ts, ip "\t" path "\t" fname (hit != "" ? "\tsig:" hit : ""))
          }
          i++
        }
      }
    ' >> "$out_file"
  done
}

acquire_lock() {
  local pid_file pid_value cmdline
  pid_file="$LOCK_DIR/pid"
  if mkdir "$LOCK_DIR" >/dev/null 2>&1; then
    printf '%s\n' "$$" > "$pid_file" 2>/dev/null || true
    return 0
  fi
  if [ -f "$pid_file" ]; then
    pid_value="$(cat "$pid_file" 2>/dev/null || echo "")"
    if is_uint "$pid_value" && kill -0 "$pid_value" >/dev/null 2>&1; then
      cmdline="$(cat "/proc/$pid_value/cmdline" 2>/dev/null || echo "")"
      case "$cmdline" in
        *"$SCRIPT_NAME"*)
          RUNNING_PID="$pid_value"
          return 1
          ;;
      esac
    fi
  fi
  rm -f "$pid_file" >/dev/null 2>&1 || true
  rmdir "$LOCK_DIR" >/dev/null 2>&1 || true
  if mkdir "$LOCK_DIR" >/dev/null 2>&1; then
    printf '%s\n' "$$" > "$pid_file" 2>/dev/null || true
    return 0
  fi
  if [ -f "$pid_file" ]; then
    pid_value="$(cat "$pid_file" 2>/dev/null || echo "")"
    if is_uint "$pid_value"; then
      RUNNING_PID="$pid_value"
    fi
  fi
  return 1
}

release_lock() {
  if [ -d "$LOCK_DIR" ]; then
    rm -f "$LOCK_DIR/pid" >/dev/null 2>&1 || true
    rmdir "$LOCK_DIR" >/dev/null 2>&1 || true
  fi
}

# État des bans en mémoire : IP -> expiration, nombre de bans, début du ban en cours.
# Format du fichier : ip|expiration|nombre|debut (les anciennes lignes "ip|expiration" restent lisibles).
load_state() {
  local ip exp count since
  while IFS='|' read -r ip exp count since || [ -n "${ip:-}" ]; do
    [ -n "${ip:-}" ] && is_uint "${exp:-}" || continue
    is_uint "${count:-}" || count=1
    is_uint "${since:-}" || since=0
    ST_EXP["$ip"]="$exp"
    ST_COUNT["$ip"]="$count"
    ST_SINCE["$ip"]="$since"
  done < "$BAN_STATE_FILE"
}

save_state() {
  local tmp_file ip
  tmp_file="$(mktemp "$BAN_STATE_FILE.XXXXXX")" || return 1
  for ip in "${!ST_EXP[@]}"; do
    printf '%s|%s|%s|%s\n' "$ip" "${ST_EXP[$ip]}" "${ST_COUNT[$ip]}" "${ST_SINCE[$ip]}"
  done > "$tmp_file"
  mv -f "$tmp_file" "$BAN_STATE_FILE"   # remplacement atomique
}

forget_ip() {
  unset 'ST_EXP[$1]' 'ST_COUNT[$1]' 'ST_SINCE[$1]'
}

# Ban en cours qui couvre déjà les derniers événements de l'IP : rien à faire, rien à journaliser
is_banned_for() {
  local ip="$1" last_ts="$2"
  [ -n "${ST_EXP[$ip]+x}" ] && [ "${ST_EXP[$ip]}" -gt "$NOW_TS" ] && [ "$last_ts" -le "${ST_SINCE[$ip]}" ]
}

cleanup_expired_bans() {
  local ip exp
  for ip in "${!ST_EXP[@]}"; do
    exp="${ST_EXP[$ip]}"
    if is_safe_ip "$ip"; then
      # IP ajoutée en whitelist après son ban : on la libère
      ipt "$ip" -D BAN-PATH-EXPLORER -s "$ip" -j DROP >/dev/null 2>&1 && log_track "Déblocage (whitelist): $ip"
      forget_ip "$ip"
      continue
    fi
    if [ "$exp" -le "$NOW_TS" ]; then
      if ipt "$ip" -C BAN-PATH-EXPLORER -s "$ip" -j DROP >/dev/null 2>&1; then
        ipt "$ip" -D BAN-PATH-EXPLORER -s "$ip" -j DROP >/dev/null 2>&1
        log_track "Déblocage expiré: $ip (bans: ${ST_COUNT[$ip]})"
      fi
      # On garde la trace un moment pour allonger le prochain ban si l'IP revient
      if [ "$exp" -le $((NOW_TS - RECIDIVE_MEMORY_SECONDS)) ]; then
        forget_ip "$ip"
      fi
    else
      # Ban encore valide mais règle absente (redémarrage, flush) : on la réapplique
      if ! ipt "$ip" -C BAN-PATH-EXPLORER -s "$ip" -j DROP >/dev/null 2>&1; then
        if is_valid_ip "$ip" && ipt "$ip" -A BAN-PATH-EXPLORER -s "$ip" -j DROP >/dev/null 2>&1; then
          log_track "Ban restauré depuis l'état: $ip (jusqu'à $(format_ymd_hm "$exp"))"
        fi
      fi
    fi
  done
}

ensure_ban_chain() {
  local cmd
  for cmd in iptables ip6tables; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      [ "$cmd" = "iptables" ] && return 1
      log_track "Avertissement: ip6tables absent, les IPv6 ne pourront pas être bannies"
      continue
    fi
    if ! "$cmd" -w -L BAN-PATH-EXPLORER -n >/dev/null 2>&1; then
      "$cmd" -w -N BAN-PATH-EXPLORER >/dev/null 2>&1 || return 1
      log_track "Chaîne $cmd créée: BAN-PATH-EXPLORER"
    fi
    if ! "$cmd" -w -C INPUT -j BAN-PATH-EXPLORER >/dev/null 2>&1; then
      "$cmd" -w -I INPUT -j BAN-PATH-EXPLORER >/dev/null 2>&1 || return 1
      log_track "Chaîne BAN-PATH-EXPLORER insérée dans INPUT ($cmd)"
    fi
  done
  return 0
}

ban_ip() {
  local ip="$1"
  if ! is_valid_ip "$ip"; then
    log_track "Ban refusé: IP invalide ou réservée: \"$ip\""
    return 1
  fi
  if is_safe_ip "$ip"; then
    log_track "Ban refusé: IP en whitelist ou locale: $ip"
    return 1
  fi
  if is_private_ip "$ip"; then
    log_track "Ban refusé: IP privée $ip (reverse proxy ? configurer mod_remoteip, voir README)"
    return 1
  fi
  if ! ipt "$ip" -C BAN-PATH-EXPLORER -s "$ip" -j DROP >/dev/null 2>&1; then
    if ! ipt "$ip" -A BAN-PATH-EXPLORER -s "$ip" -j DROP >/dev/null 2>&1; then
      log_track "Erreur ban iptables: $ip"
      return 1
    fi
  fi
  local count=$(( ${ST_COUNT[$ip]:-0} + 1 ))
  local step=$((count > ${#RECIDIVE_MINUTES[@]} ? ${#RECIDIVE_MINUTES[@]} - 1 : count - 1))
  local duration=$(( RECIDIVE_MINUTES[step] * 60 ))
  [ "$duration" -lt "$BAN_DURATION_SECONDS" ] && duration="$BAN_DURATION_SECONDS"
  ST_COUNT["$ip"]="$count"
  ST_SINCE["$ip"]="$NOW_TS"
  ST_EXP["$ip"]=$((NOW_TS + duration))
  BAN_UNTIL="${ST_EXP[$ip]}"
  BAN_COUNT="$count"
  log_track "IP bannie: $ip (ban n°$count, $((duration / 60)) min, jusqu'à $(format_ymd_hm "$BAN_UNTIL"))"
  return 0
}

format_hm() {
  if date -d "@$1" '+%H:%M' >/dev/null 2>&1; then
    date -d "@$1" '+%H:%M'
  else
    date -r "$1" '+%H:%M'
  fi
}

format_ymd_hm() {
  if date -d "@$1" '+%Y-%m-%d %H:%M' >/dev/null 2>&1; then
    date -d "@$1" '+%Y-%m-%d %H:%M'
  else
    date -r "$1" '+%Y-%m-%d %H:%M'
  fi
}

run_follow_mode() {
  local -a follow_cmd=()
  local cycle=0
  local rc=0

  follow_cmd=(bash "$SCRIPT_DIR/$SCRIPT_NAME" --log-dir "$LOG_DIR" --threshold "$THRESHOLD" --window "$WINDOW_MINUTES" --max-log-lines "$MAX_LOG_LINES" --max-events "$MAX_EVENTS" --lock-dir "$LOCK_DIR")
  if [ -n "$LOG_FILES_RAW" ]; then
    follow_cmd+=(--log-files "$LOG_FILES_RAW")
  fi
  if [ -n "$IGNORE_PATHS_RAW" ]; then
    follow_cmd+=(--ignore-paths "$IGNORE_PATHS_RAW")
  fi
  if [ "$BAN_ENABLED" -eq 1 ]; then
    follow_cmd+=(--ban --ban-duration "$BAN_DURATION_MINUTES")
  fi
  if [ "$QUIET" -eq 1 ]; then
    follow_cmd+=(--quiet)
  fi

  build_log_files_list
  warn_uncovered_logs   # une seule fois, pas à chaque cycle
  say "Mode continu activé (intervalle: ${FOLLOW_INTERVAL_SECONDS}s)"
  log_track "Mode continu activé | interval=${FOLLOW_INTERVAL_SECONDS}s"

  while :; do
    cycle=$((cycle + 1))
    BAN_PATH_FOLLOW_CHILD=1 "${follow_cmd[@]}"
    rc=$?
    if [ "$rc" -ne 0 ]; then
      log_track "Cycle follow en erreur | cycle=$cycle | code=$rc"
    fi
    sleep "$FOLLOW_INTERVAL_SECONDS"
  done
}

main() {
  local now_header tmp_parsed tmp_events tmp_sorted tmp_suspects
  local analyzed_count=0
  local line_ts line_ip line_path line_file
  local unix_ts
  local threshold_reached=0
  local total_records=0
  local suspect_count=0
  local ip first_paths
  local first_epoch last_epoch unique_count
  local action_line
  local expiry_now
  local capped_events=0
  local orig_args="$*"

  while [ $# -gt 0 ]; do
    case "$1" in
      --log-dir)
        shift
        [ $# -gt 0 ] || { printf 'Option --log-dir invalide\n' >&2; return 1; }
        LOG_DIR="$1"
        ;;
      --log-files)
        shift
        [ $# -gt 0 ] || { printf 'Option --log-files invalide\n' >&2; return 1; }
        LOG_FILES_RAW="$1"
        ;;
      --threshold)
        shift
        [ $# -gt 0 ] || { printf 'Option --threshold invalide\n' >&2; return 1; }
        THRESHOLD="$1"
        ;;
      --window)
        shift
        [ $# -gt 0 ] || { printf 'Option --window invalide\n' >&2; return 1; }
        WINDOW_MINUTES="$1"
        ;;
      --ban)
        BAN_ENABLED=1
        ;;
      --ban-duration)
        shift
        [ $# -gt 0 ] || { printf 'Option --ban-duration invalide\n' >&2; return 1; }
        BAN_DURATION_MINUTES="$1"
        ;;
      --ignore-paths)
        shift
        [ $# -gt 0 ] || { printf 'Option --ignore-paths invalide\n' >&2; return 1; }
        IGNORE_PATHS_RAW="$1"
        ;;
      --max-log-lines)
        shift
        [ $# -gt 0 ] || { printf 'Option --max-log-lines invalide\n' >&2; return 1; }
        MAX_LOG_LINES="$1"
        ;;
      --max-events)
        shift
        [ $# -gt 0 ] || { printf 'Option --max-events invalide\n' >&2; return 1; }
        MAX_EVENTS="$1"
        ;;
      --follow)
        FOLLOW_MODE=1
        ;;
      --follow-interval)
        shift
        [ $# -gt 0 ] || { printf 'Option --follow-interval invalide\n' >&2; return 1; }
        FOLLOW_INTERVAL_SECONDS="$1"
        ;;
      --lock-dir)
        shift
        [ $# -gt 0 ] || { printf 'Option --lock-dir invalide\n' >&2; return 1; }
        LOCK_DIR="$1"
        ;;
      --quiet)
        QUIET=1
        ;;
      --history)
        HISTORY_MODE=1
        ;;
      --help)
        print_usage
        return 0
        ;;
      *)
        printf 'Option inconnue: %s\n' "$1" >&2
        print_usage >&2
        return 1
        ;;
    esac
    shift
  done

  if ! is_uint "$THRESHOLD" || [ "$THRESHOLD" -eq 0 ]; then
    printf 'Erreur: --threshold doit être un entier positif\n' >&2
    return 1
  fi
  if ! is_uint "$WINDOW_MINUTES" || [ "$WINDOW_MINUTES" -eq 0 ]; then
    printf 'Erreur: --window doit être un entier positif\n' >&2
    return 1
  fi
  if ! is_uint "$BAN_DURATION_MINUTES" || [ "$BAN_DURATION_MINUTES" -eq 0 ]; then
    printf 'Erreur: --ban-duration doit être un entier positif\n' >&2
    return 1
  fi
  if ! is_uint "$MAX_LOG_LINES" || [ "$MAX_LOG_LINES" -eq 0 ]; then
    printf 'Erreur: --max-log-lines doit être un entier positif\n' >&2
    return 1
  fi
  if ! is_uint "$MAX_EVENTS" || [ "$MAX_EVENTS" -eq 0 ]; then
    printf 'Erreur: --max-events doit être un entier positif\n' >&2
    return 1
  fi
  if ! is_uint "$FOLLOW_INTERVAL_SECONDS" || [ "$FOLLOW_INTERVAL_SECONDS" -eq 0 ]; then
    printf 'Erreur: --follow-interval doit être un entier positif\n' >&2
    return 1
  fi

  if [ "$REQUIRE_ROOT" = "1" ] && [ "$(id -u)" -ne 0 ]; then
    printf 'Erreur : ce script doit être lancé avec sudo (accès aux logs Apache, iptables, /var/lib, /run).\n' >&2
    printf '  sudo %s %s\n' "$0" "$orig_args" >&2
    return 1
  fi

  WINDOW_SECONDS=$((WINDOW_MINUTES * 60))
  BAN_DURATION_SECONDS=$((BAN_DURATION_MINUTES * 60))

  if [ "$FOLLOW_MODE" -eq 1 ]; then
    run_follow_mode
    return 0
  fi

  if ! setup_tracking_files; then
    printf 'Erreur: impossible de préparer %s ou %s\n' "$TRACK_LOG" "$BAN_STATE_FILE" >&2
    return 1
  fi
  if ! ensure_safe_ips_file; then
    log_track "Erreur: impossible de préparer la whitelist: $SAFE_IPS_FILE"
    printf 'Erreur: impossible de préparer la whitelist: %s\n' "$SAFE_IPS_FILE" >&2
    return 1
  fi
  if ! acquire_lock; then
    if [ -n "$RUNNING_PID" ]; then
      log_track "Exécution ignorée: instance déjà en cours (PID=$RUNNING_PID, lock=$LOCK_DIR)"
      printf 'Erreur: une exécution est déjà en cours (PID=%s)\n' "$RUNNING_PID" >&2
    else
      log_track "Exécution ignorée: verrou déjà présent ($LOCK_DIR)"
      printf 'Erreur: une exécution est déjà en cours (%s)\n' "$LOCK_DIR" >&2
    fi
    return 1
  fi
  # Fichiers de travail dans un dossier privé (mktemp : nom imprévisible, mode 700)
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ban-path-explorer.XXXXXX")" || { release_lock; return 1; }
  trap 'release_lock; rm -rf "$WORK_DIR"' EXIT
  trap 'exit 1' INT TERM

  load_safe_ips
  load_local_ips
  parse_ignore_paths
  build_log_files_list
  [ "${BAN_PATH_FOLLOW_CHILD:-0}" = "1" ] || warn_uncovered_logs

  analyzed_count="${#LOG_FILES[@]}"
  now_header="$(date '+%Y-%m-%d %H:%M')"
  say "[$now_header] Ban Path Explorer v$VERSION"
  say "Analysé : $analyzed_count fichiers log (error + access)"
  say "Fenêtre : $WINDOW_MINUTES minutes | Seuil : $THRESHOLD URLs différentes"

  log_routine "Démarrage v$VERSION | log-dir=$LOG_DIR | files=\"$LOG_FILES_RAW\" | threshold=$THRESHOLD | window=$WINDOW_MINUTES | ban=$BAN_ENABLED | ban-duration=$BAN_DURATION_MINUTES | quiet=$QUIET | ignore=\"$IGNORE_PATHS_RAW\" | max-log-lines=$MAX_LOG_LINES | max-events=$MAX_EVENTS | lock-dir=$LOCK_DIR"

  if [ "$analyzed_count" -eq 0 ]; then
    log_routine "Aucun fichier log trouvé"
    say "Aucun fichier log à analyser"
    say "(enregistré dans $TRACK_LOG)"
    return 0
  fi

  for ip in "${LOG_FILES[@]}"; do
    log_routine "Fichier analysé: $ip"
  done

  tmp_parsed="$WORK_DIR/parsed"
  tmp_events="$WORK_DIR/events"
  tmp_sorted="$WORK_DIR/sorted"
  tmp_suspects="$WORK_DIR/suspects"

  : > "$tmp_parsed"
  : > "$tmp_events"
  : > "$tmp_sorted"
  : > "$tmp_suspects"

  parse_logs_to_tmp "$tmp_parsed"

  local line_kind
  [ -f "$BAD_PATTERNS_FILE" ] || log_track "Avertissement: $BAD_PATTERNS_FILE absent, aucun ban par signature"
  while IFS=$'\t' read -r line_ts line_ip line_path line_file line_kind || [ -n "${line_ts}${line_ip}${line_path}${line_file}" ]; do
    [ -z "${line_ts:-}" ] && continue
    [ -z "${line_ip:-}" ] && continue
    [ -z "${line_path:-}" ] && continue

    if is_safe_ip "$line_ip"; then
      continue
    fi
    if should_ignore_path "$line_path"; then
      continue
    fi
    # Horodatage déjà converti et filtré sur la fenêtre par l'awk de parsing (événements récents seulement)
    unix_ts="$line_ts"
    is_uint "$unix_ts" || continue
    if [ -z "${LAST_TS[$line_ip]+x}" ] || [ "$unix_ts" -gt "${LAST_TS[$line_ip]}" ]; then
      LAST_TS["$line_ip"]="$unix_ts"
    fi
    # Signature d'attaque : ban immédiat, sans seuil
    if [ "${line_kind#sig:}" != "${line_kind:-}" ] && [ -z "${SIG_HIT[$line_ip]+x}" ]; then
      SIG_HIT["$line_ip"]="${line_kind#sig:} -> $line_path"
    fi
    printf '%s|%s|%s\n' "$line_ip" "$unix_ts" "$line_path"
    total_records=$((total_records + 1))
    if [ "$total_records" -ge "$MAX_EVENTS" ]; then
      capped_events=1
      break
    fi
  done < "$tmp_parsed" > "$tmp_events"

  if [ -s "$tmp_events" ]; then
    sort -t'|' -k1,1 -k2,2n "$tmp_events" > "$tmp_sorted"
  fi

  # Fenêtre glissante par IP (événements triés par IP puis date), en un seul passage awk :
  # nombre maximal de chemins distincts dans une fenêtre de --window minutes.
  # ponytail: clé = dernier segment du chemin, pour ne pas compter deux fois le même 404 vu
  # dans error.log (/var/www/site/x.php) et access.log (/x.php). Sous-compte /a/x.php vs /b/x.php.
  local w_ip w_count w_start w_end w_total w_paths
  while IFS=$'\t' read -r w_ip w_count w_start w_end w_total w_paths; do
    [ -n "$w_ip" ] || continue
    threshold_reached=1
    BEST_COUNT["$w_ip"]="$w_count"
    BEST_START["$w_ip"]="$w_start"
    BEST_END["$w_ip"]="$w_end"
    BEST_TOTAL_EVENTS["$w_ip"]="$w_total"
    BEST_PATHS["$w_ip"]="$w_paths"
  done < <(awk -F'|' -v win="$WINDOW_SECONDS" -v thr="$THRESHOLD" '
    function flush(   k, list, c) {
      if (best > 0) print cur "\t" best "\t" bs "\t" be "\t" bt "\t" bp
    }
    $1 != cur {
      flush()
      cur = $1; n = 0; head = 1; uniq = 0; best = 0
      delete cnt; delete sample
    }
    {
      ts = $2 + 0
      path = substr($0, length($1) + length($2) + 3)
      k = path; sub(/\/$/, "", k); sub(/.*\//, "", k); if (k == "") k = "/"
      n++; T[n] = ts; K[n] = k; sample[k] = path
      if (cnt[k]++ == 0) uniq++
      while (T[head] < ts - win) {
        if (--cnt[K[head]] == 0) { delete cnt[K[head]]; uniq-- }
        head++
      }
      if (uniq >= thr && uniq > best) {
        best = uniq; bs = T[head]; be = ts; bt = n - head + 1
        bp = ""; c = 0
        for (x in cnt) { if (c++ < 10) bp = bp (bp == "" ? "" : ", ") sample[x] }
      }
    }
    END { flush() }
  ' "$tmp_sorted" 2>/dev/null)

  if [ "$BAN_ENABLED" -eq 1 ]; then
    if ! ensure_ban_chain; then
      log_track "Erreur iptables: impossible d'initialiser la chaîne BAN-PATH-EXPLORER"
      say "Erreur: impossible d'initialiser la chaîne IPTables BAN-PATH-EXPLORER"
      return 1
    fi
    load_state
    cleanup_expired_bans
  fi

  for ip in "${!BEST_COUNT[@]}" "${!SIG_HIT[@]}"; do
    printf '%s\n' "$ip" >> "$tmp_suspects"
  done

  if [ -s "$tmp_suspects" ]; then
    while IFS= read -r ip || [ -n "$ip" ]; do
      [ -z "$ip" ] && continue
      suspect_count=$((suspect_count + 1))
      if [ "$BAN_ENABLED" -eq 1 ] && is_banned_for "$ip" "${LAST_TS[$ip]}"; then
        say "IP déjà bannie : $ip (jusqu'à $(format_hm "${ST_EXP[$ip]}"), aucun nouvel événement)"
        continue
      fi
      say "IP suspecte : $ip"
      if [ -n "${BEST_COUNT[$ip]+x}" ]; then
        first_epoch="${BEST_START[$ip]}"
        last_epoch="${BEST_END[$ip]}"
        unique_count="${BEST_COUNT[$ip]}"
        first_paths="${BEST_PATHS[$ip]}"
        say "→ $unique_count URLs différentes entre $(format_hm "$first_epoch") et $(format_hm "$last_epoch")"
        if [ -n "$first_paths" ]; then
          say "Chemins : $first_paths"
        else
          say "Chemins : (aucun aperçu disponible)"
        fi
        log_track "IP suspecte: $ip | unique_urls=$unique_count | events_window=${BEST_TOTAL_EVENTS[$ip]} | from=$(format_ymd_hm "$first_epoch") | to=$(format_ymd_hm "$last_epoch") | paths=\"$first_paths\""
      fi
      if [ -n "${SIG_HIT[$ip]+x}" ]; then
        say "→ Signature d'attaque : ${SIG_HIT[$ip]}"
        log_track "IP suspecte: $ip | signature=\"${SIG_HIT[$ip]}\""
      fi

      if [ "$BAN_ENABLED" -eq 1 ]; then
        if ban_ip "$ip"; then
          action_line="ban n°$BAN_COUNT appliqué jusqu'à $(format_ymd_hm "$BAN_UNTIL")"
        else
          action_line="ban échoué"
        fi
      else
        action_line="dry-run -> aucune règle IPTables appliquée"
      fi
      say "Action : $action_line"
      log_track "Action pour $ip: $action_line"
    done < <(sort -u "$tmp_suspects")
  fi
  if [ "$BAN_ENABLED" -eq 1 ]; then
    save_state
  fi

  if [ "$suspect_count" -eq 0 ]; then
    say "Aucune IP suspecte détectée"
    log_routine "Aucune IP suspecte détectée | lignes_utiles=$total_records"
  fi
  if [ "$capped_events" -eq 1 ]; then
    say "Limite atteinte : $MAX_EVENTS événements traités"
    log_track "Limite atteinte: max-events=$MAX_EVENTS"
  fi

  if [ "$BAN_ENABLED" -eq 0 ]; then
    say "Action : dry-run -> aucune règle IPTables appliquée"
  fi
  say "(enregistré dans $TRACK_LOG)"

  log_routine "Fin d'exécution | fichiers=$analyzed_count | lignes_utiles=$total_records | suspects=$suspect_count | seuil_atteint=$threshold_reached"

}

early_help_return "$@"
if [ "$?" -eq 0 ]; then
  :
else
  main "$@"
fi
