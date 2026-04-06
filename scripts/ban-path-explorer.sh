#!/usr/bin/env bash
#
# Usage : ban-path-explorer.sh [options]
# Exemples :
#   ./ban-path-explorer.sh
#   nohup ./ban-path-explorer.sh --log-dir /var/log/apache2 > /tmp/ban-path-explorer.out 2>&1 &
#   ./ban-path-explorer.sh --log-dir /var/log/apache2 --threshold 25 --window 20
#   ./ban-path-explorer.sh --log-files "error.log error_site.log" --ignore-paths "favicon.ico,robots.txt"
#   ./ban-path-explorer.sh --ban --ban-duration 60
#
# Exemple de contenu safe-ips.txt :
#   127.0.0.1
#   ::1
#   203.0.113.10

set -u

VERSION="1.0"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAFE_IPS_FILE="$SCRIPT_DIR/safe-ips.txt"
TRACK_LOG="/var/log/ban-path-explorer.log"
BAN_STATE_FILE="/var/log/ban-path-explorer.state"
LOCK_DIR_BASE="/tmp/ban-path-explorer.lock"

DEFAULT_LOG_DIR="/var/log/apache2"
DEFAULT_THRESHOLD="20"
DEFAULT_WINDOW_MINUTES="30"
DEFAULT_BAN_DURATION_MINUTES="60"
DEFAULT_IGNORE_PATHS=""
DEFAULT_QUIET="0"
DEFAULT_BAN="0"
DEFAULT_MAX_LOG_LINES="20000"
DEFAULT_MAX_EVENTS="200000"

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

WINDOW_SECONDS="0"
BAN_DURATION_SECONDS="0"

declare -a LOG_FILES=()
declare -a IGNORE_PATHS=()
declare -A SAFE_IPS=()
declare -A BEST_COUNT=()
declare -A BEST_START=()
declare -A BEST_END=()
declare -A BEST_PATHS=()
declare -A BEST_TOTAL_EVENTS=()
declare -A TS_CACHE=()
RUNNING_PID=""

print_usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Exécution en arrière-plan:
  nohup ./$SCRIPT_NAME --log-dir $DEFAULT_LOG_DIR > /tmp/ban-path-explorer.out 2>&1 &

Options:
  --log-dir DIR            Dossier des logs Apache (défaut: $DEFAULT_LOG_DIR)
  --log-files "F1 F2 ..."  Liste de fichiers logs séparés par des espaces
  --threshold N            Seuil d'URLs différentes par IP (défaut: $DEFAULT_THRESHOLD)
  --window MIN             Fenêtre glissante en minutes (défaut: $DEFAULT_WINDOW_MINUTES)
  --max-log-lines N        Max lignes lues par fichier log (défaut: $DEFAULT_MAX_LOG_LINES)
  --max-events N           Max événements traités par exécution (défaut: $DEFAULT_MAX_EVENTS)
  --lock-dir DIR           Verrou d'exécution unique (défaut: $LOCK_DIR_BASE)
  --ignore-paths "a,b,c"   Ignore les chemins contenant ces motifs
  --ban                    Active le blocage IPTables
  --ban-duration MIN       Durée de blocage en minutes (défaut: $DEFAULT_BAN_DURATION_MINUTES)
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

setup_tracking_files() {
  local track_dir state_dir
  track_dir="$(dirname "$TRACK_LOG")"
  state_dir="$(dirname "$BAN_STATE_FILE")"
  if [ ! -d "$track_dir" ]; then
    mkdir -p "$track_dir" 2>/dev/null || return 1
  fi
  if [ ! -d "$state_dir" ]; then
    mkdir -p "$state_dir" 2>/dev/null || return 1
  fi
  touch "$TRACK_LOG" 2>/dev/null || return 1
  touch "$BAN_STATE_FILE" 2>/dev/null || return 1
  return 0
}

get_server_public_ipv4() {
  ip -4 addr show scope global 2>/dev/null | awk '
    /inet / {
      split($2, a, "/");
      ip=a[1];
      if (ip ~ /^127\./) next;
      if (ip ~ /^10\./) next;
      if (ip ~ /^192\.168\./) next;
      if (ip ~ /^172\./) {
        split(ip, b, ".");
        if (b[2] >= 16 && b[2] <= 31) next;
      }
      print ip;
    }
  '
}

ensure_safe_ips_file() {
  local server_ip
  if [ ! -f "$SAFE_IPS_FILE" ]; then
    return 1
  fi
  server_ip="$(get_server_public_ipv4)"
  if [ -n "$server_ip" ] && ! grep -Fxq "$server_ip" "$SAFE_IPS_FILE" 2>/dev/null; then
    printf '%s\n' "$server_ip" >> "$SAFE_IPS_FILE" 2>/dev/null || return 1
  fi
  return 0
}

load_safe_ips() {
  local ip_line cleaned
  while IFS= read -r ip_line || [ -n "$ip_line" ]; do
    cleaned="$(trim_spaces "$ip_line")"
    [ -z "$cleaned" ] && continue
    SAFE_IPS["$cleaned"]=1
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

apache_to_unix_ts() {
  local apache_ts="$1"
  local first rest normalized
  local cleaned
  if [ -z "$apache_ts" ]; then
    return 1
  fi

  # Format Apache classique: 06/Apr/2026:18:07:29 +0000
  if printf '%s' "$apache_ts" | grep -Eq '^[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:'; then
    first="${apache_ts%%:*}"
    rest="${apache_ts#*:}"
    normalized="$first $rest"
    if date -d "$normalized" '+%s' >/dev/null 2>&1; then
      date -d "$normalized" '+%s' 2>/dev/null
      return 0
    fi
    date -j -f '%d/%b/%Y %H:%M:%S %z' "$normalized" '+%s' 2>/dev/null
    return $?
  fi

  # Format error log moderne: Mon Apr 06 18:07:29.239286 2026
  if date -d "$apache_ts" '+%s' >/dev/null 2>&1; then
    date -d "$apache_ts" '+%s' 2>/dev/null
    return 0
  fi
  cleaned="$(printf '%s' "$apache_ts" | sed -E 's/([0-9]{2}:[0-9]{2}:[0-9]{2})\.[0-9]+/\1/')"
  date -j -f '%a %b %d %H:%M:%S %Y' "$cleaned" '+%s' 2>/dev/null
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
    for f in "$LOG_DIR"/error*.log; do
      [ -f "$f" ] || continue
      LOG_FILES+=("$f")
    done
  fi
}

parse_logs_to_tmp() {
  local out_file="$1"
  local f
  : > "$out_file"
  for f in "${LOG_FILES[@]}"; do
    awk -v max="$MAX_LOG_LINES" '
      {
        buf[NR % max] = $0
      }
      END {
        start = (NR > max) ? NR - max + 1 : 1
        i = start
        while (i <= NR) {
          line = buf[i % max]
          if (line ~ /\[[^]]*error\]/ &&
              (line ~ /File does not exist: / ||
               line ~ /AH01276:/ ||
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
                if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/) {
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
            if (pos > 0) {
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
            print ts "\t" ip "\t" path "\t" FILENAME
          }
          i++
        }
      }
    ' "$f" >> "$out_file"
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

cleanup_expired_bans() {
  local now_ts tmp_file ip exp
  now_ts="$(date '+%s')"
  tmp_file="/tmp/${SCRIPT_NAME}.state.$$"
  : > "$tmp_file"
  while IFS='|' read -r ip exp || [ -n "${ip}${exp}" ]; do
    [ -z "${ip:-}" ] && continue
    [ -z "${exp:-}" ] && continue
    if ! is_uint "$exp"; then
      continue
    fi
    if [ "$exp" -le "$now_ts" ]; then
      if iptables -C BAN-PATH-EXPLORER -s "$ip" -j DROP >/dev/null 2>&1; then
        iptables -D BAN-PATH-EXPLORER -s "$ip" -j DROP >/dev/null 2>&1
        log_track "Déblocage expiré: $ip"
      fi
    else
      printf '%s|%s\n' "$ip" "$exp" >> "$tmp_file"
    fi
  done < "$BAN_STATE_FILE"
  cat "$tmp_file" > "$BAN_STATE_FILE"
  rm -f "$tmp_file"
}

ensure_ban_chain() {
  if ! iptables -L BAN-PATH-EXPLORER -n >/dev/null 2>&1; then
    iptables -N BAN-PATH-EXPLORER >/dev/null 2>&1 || return 1
    log_track "Chaîne iptables créée: BAN-PATH-EXPLORER"
  fi
  if ! iptables -C INPUT -j BAN-PATH-EXPLORER >/dev/null 2>&1; then
    iptables -I INPUT -j BAN-PATH-EXPLORER >/dev/null 2>&1 || return 1
    log_track "Chaîne BAN-PATH-EXPLORER insérée dans INPUT"
  fi
  return 0
}

update_ban_state() {
  local target_ip="$1"
  local expiry="$2"
  local tmp_file ip exp
  tmp_file="/tmp/${SCRIPT_NAME}.stateup.$$"
  : > "$tmp_file"
  while IFS='|' read -r ip exp || [ -n "${ip}${exp}" ]; do
    [ -z "${ip:-}" ] && continue
    [ "$ip" = "$target_ip" ] && continue
    if is_uint "${exp:-}"; then
      printf '%s|%s\n' "$ip" "$exp" >> "$tmp_file"
    fi
  done < "$BAN_STATE_FILE"
  printf '%s|%s\n' "$target_ip" "$expiry" >> "$tmp_file"
  cat "$tmp_file" > "$BAN_STATE_FILE"
  rm -f "$tmp_file"
}

ban_ip() {
  local ip="$1"
  local until_ts="$2"
  if iptables -C BAN-PATH-EXPLORER -s "$ip" -j DROP >/dev/null 2>&1; then
    update_ban_state "$ip" "$until_ts"
    log_track "IP déjà bannie: règle iptables existante, aucun ajout: $ip (expiration mise à jour: $until_ts)"
    return 0
  fi
  if iptables -A BAN-PATH-EXPLORER -s "$ip" -j DROP >/dev/null 2>&1; then
    update_ban_state "$ip" "$until_ts"
    log_track "IP bannie: $ip (jusqu'à $until_ts)"
    return 0
  fi
  log_track "Erreur ban iptables: $ip"
  return 1
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

main() {
  local now_header tmp_parsed tmp_events tmp_sorted tmp_suspects
  local analyzed_count=0
  local line_ts line_ip line_path line_file
  local unix_ts
  local window_start
  local current_ip=""
  local idx=0
  local threshold_reached=0
  local total_records=0
  local suspect_count=0
  local ip first_paths max_paths
  local first_epoch last_epoch unique_count total_in_window
  local old_path
  local action_line
  local expiry_now
  local capped_events=0

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
      --lock-dir)
        shift
        [ $# -gt 0 ] || { printf 'Option --lock-dir invalide\n' >&2; return 1; }
        LOCK_DIR="$1"
        ;;
      --quiet)
        QUIET=1
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

  WINDOW_SECONDS=$((WINDOW_MINUTES * 60))
  BAN_DURATION_SECONDS=$((BAN_DURATION_MINUTES * 60))

  if ! setup_tracking_files; then
    printf 'Erreur: impossible de préparer %s ou %s\n' "$TRACK_LOG" "$BAN_STATE_FILE" >&2
    return 1
  fi
  if ! ensure_safe_ips_file; then
    log_track "Erreur: fichier whitelist manquant: $SAFE_IPS_FILE"
    printf 'Erreur: fichier whitelist introuvable: %s\n' "$SAFE_IPS_FILE" >&2
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
  trap 'release_lock' return INT TERM

  load_safe_ips
  parse_ignore_paths
  build_log_files_list

  analyzed_count="${#LOG_FILES[@]}"
  now_header="$(date '+%Y-%m-%d %H:%M')"
  say "[$now_header] Ban Path Explorer v$VERSION"
  say "Analysé : $analyzed_count fichiers error*.log"
  say "Fenêtre : $WINDOW_MINUTES minutes | Seuil : $THRESHOLD URLs différentes"

  log_track "Démarrage v$VERSION | log-dir=$LOG_DIR | files=\"$LOG_FILES_RAW\" | threshold=$THRESHOLD | window=$WINDOW_MINUTES | ban=$BAN_ENABLED | ban-duration=$BAN_DURATION_MINUTES | quiet=$QUIET | ignore=\"$IGNORE_PATHS_RAW\" | max-log-lines=$MAX_LOG_LINES | max-events=$MAX_EVENTS | lock-dir=$LOCK_DIR"

  if [ "$analyzed_count" -eq 0 ]; then
    log_track "Aucun fichier log trouvé"
    say "Aucun fichier log à analyser"
    say "(enregistré dans $TRACK_LOG)"
    return 0
  fi

  for ip in "${LOG_FILES[@]}"; do
    log_track "Fichier analysé: $ip"
  done

  tmp_parsed="/tmp/${SCRIPT_NAME}.parsed.$$"
  tmp_events="/tmp/${SCRIPT_NAME}.events.$$"
  tmp_sorted="/tmp/${SCRIPT_NAME}.sorted.$$"
  tmp_suspects="/tmp/${SCRIPT_NAME}.suspects.$$"

  : > "$tmp_parsed"
  : > "$tmp_events"
  : > "$tmp_sorted"
  : > "$tmp_suspects"

  parse_logs_to_tmp "$tmp_parsed"

  while IFS=$'\t' read -r line_ts line_ip line_path line_file || [ -n "${line_ts}${line_ip}${line_path}${line_file}" ]; do
    [ -z "${line_ts:-}" ] && continue
    [ -z "${line_ip:-}" ] && continue
    [ -z "${line_path:-}" ] && continue

    if [ -n "${SAFE_IPS[$line_ip]+x}" ]; then
      continue
    fi
    if should_ignore_path "$line_path"; then
      continue
    fi

    if [ -n "${TS_CACHE[$line_ts]+x}" ]; then
      unix_ts="${TS_CACHE[$line_ts]}"
    else
      unix_ts="$(apache_to_unix_ts "$line_ts")"
      if [ -n "$unix_ts" ] && is_uint "$unix_ts"; then
        TS_CACHE["$line_ts"]="$unix_ts"
      fi
    fi
    [ -z "$unix_ts" ] && continue
    if ! is_uint "$unix_ts"; then
      continue
    fi
    printf '%s|%s|%s\n' "$line_ip" "$unix_ts" "$line_path" >> "$tmp_events"
    total_records=$((total_records + 1))
    if [ "$total_records" -ge "$MAX_EVENTS" ]; then
      capped_events=1
      break
    fi
  done < "$tmp_parsed"

  if [ -s "$tmp_events" ]; then
    sort -t'|' -k1,1 -k2,2n "$tmp_events" > "$tmp_sorted"
  fi

  declare -a WINDOW_TS=()
  declare -a WINDOW_PATHS=()
  declare -A WINDOW_PATH_COUNT=()

  while IFS='|' read -r line_ip unix_ts line_path || [ -n "${line_ip}${unix_ts}${line_path}" ]; do
    [ -z "${line_ip:-}" ] && continue
    [ -z "${unix_ts:-}" ] && continue
    [ -z "${line_path:-}" ] && continue

    if [ "$line_ip" != "$current_ip" ]; then
      current_ip="$line_ip"
      WINDOW_TS=()
      WINDOW_PATHS=()
      unset WINDOW_PATH_COUNT
      declare -A WINDOW_PATH_COUNT=()
      idx=0
    fi

    WINDOW_TS+=("$unix_ts")
    WINDOW_PATHS+=("$line_path")
    if [ -n "${WINDOW_PATH_COUNT[$line_path]+x}" ]; then
      WINDOW_PATH_COUNT["$line_path"]=$((WINDOW_PATH_COUNT["$line_path"] + 1))
    else
      WINDOW_PATH_COUNT["$line_path"]=1
    fi

    window_start=$((unix_ts - WINDOW_SECONDS))
    while [ "$idx" -lt "${#WINDOW_TS[@]}" ] && [ "${WINDOW_TS[$idx]}" -lt "$window_start" ]; do
      old_path="${WINDOW_PATHS[$idx]}"
      if [ -n "${WINDOW_PATH_COUNT[$old_path]+x}" ]; then
        WINDOW_PATH_COUNT["$old_path"]=$((WINDOW_PATH_COUNT["$old_path"] - 1))
        if [ "${WINDOW_PATH_COUNT[$old_path]}" -le 0 ]; then
          unset 'WINDOW_PATH_COUNT[$old_path]'
        fi
      fi
      idx=$((idx + 1))
    done

    unique_count="${#WINDOW_PATH_COUNT[@]}"
    total_in_window=$(( ${#WINDOW_TS[@]} - idx ))
    if [ "$unique_count" -ge "$THRESHOLD" ]; then
      threshold_reached=1
      if [ -z "${BEST_COUNT[$line_ip]+x}" ] || [ "$unique_count" -gt "${BEST_COUNT[$line_ip]}" ]; then
        BEST_COUNT["$line_ip"]="$unique_count"
        BEST_START["$line_ip"]="${WINDOW_TS[$idx]}"
        BEST_END["$line_ip"]="$unix_ts"
        BEST_TOTAL_EVENTS["$line_ip"]="$total_in_window"
        first_paths=""
        max_paths=0
        for ip in "${!WINDOW_PATH_COUNT[@]}"; do
          if [ "$max_paths" -lt 10 ]; then
            if [ -z "$first_paths" ]; then
              first_paths="$ip"
            else
              first_paths="$first_paths, $ip"
            fi
          fi
          max_paths=$((max_paths + 1))
        done
        BEST_PATHS["$line_ip"]="$first_paths"
      fi
    fi
  done < "$tmp_sorted"

  if [ "$BAN_ENABLED" -eq 1 ]; then
    if ! ensure_ban_chain; then
      log_track "Erreur iptables: impossible d'initialiser la chaîne BAN-PATH-EXPLORER"
      say "Erreur: impossible d'initialiser la chaîne IPTables BAN-PATH-EXPLORER"
      rm -f "$tmp_parsed" "$tmp_events" "$tmp_sorted" "$tmp_suspects"
      return 1
    fi
    cleanup_expired_bans
  fi

  for ip in "${!BEST_COUNT[@]}"; do
    printf '%s\n' "$ip" >> "$tmp_suspects"
  done

  if [ -s "$tmp_suspects" ]; then
    while IFS= read -r ip || [ -n "$ip" ]; do
      [ -z "$ip" ] && continue
      suspect_count=$((suspect_count + 1))
      first_epoch="${BEST_START[$ip]}"
      last_epoch="${BEST_END[$ip]}"
      unique_count="${BEST_COUNT[$ip]}"
      first_paths="${BEST_PATHS[$ip]}"

      say "IP suspecte : $ip"
      say "→ $unique_count URLs différentes entre $(format_hm "$first_epoch") et $(format_hm "$last_epoch")"
      if [ -n "$first_paths" ]; then
        say "Chemins : $first_paths"
      else
        say "Chemins : (aucun aperçu disponible)"
      fi

      log_track "IP suspecte: $ip | unique_urls=$unique_count | events_window=${BEST_TOTAL_EVENTS[$ip]} | from=$(format_ymd_hm "$first_epoch") | to=$(format_ymd_hm "$last_epoch") | paths=\"$first_paths\""

      if [ "$BAN_ENABLED" -eq 1 ]; then
        expiry_now=$(( $(date '+%s') + BAN_DURATION_SECONDS ))
        if ban_ip "$ip" "$expiry_now"; then
          action_line="ban appliqué ($BAN_DURATION_MINUTES min)"
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

  if [ "$suspect_count" -eq 0 ]; then
    say "Aucune IP suspecte détectée"
    log_track "Aucune IP suspecte détectée | lignes_utiles=$total_records"
  fi
  if [ "$capped_events" -eq 1 ]; then
    say "Limite atteinte : $MAX_EVENTS événements traités"
    log_track "Limite atteinte: max-events=$MAX_EVENTS"
  fi

  if [ "$BAN_ENABLED" -eq 0 ]; then
    say "Action : dry-run -> aucune règle IPTables appliquée"
  fi
  say "(enregistré dans $TRACK_LOG)"

  log_track "Fin d'exécution | fichiers=$analyzed_count | lignes_utiles=$total_records | suspects=$suspect_count | seuil_atteint=$threshold_reached"

  rm -f "$tmp_parsed" "$tmp_events" "$tmp_sorted" "$tmp_suspects"
}

early_help_return "$@"
if [ "$?" -eq 0 ]; then
  :
else
  main "$@"
fi
