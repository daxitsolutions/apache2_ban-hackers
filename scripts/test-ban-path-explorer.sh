#!/usr/bin/env bash
#
# Usage : ./scripts/test-ban-path-explorer.sh
# Lance une batterie de tests isolée sur ban-path-explorer.sh
# sans jamais modifier les fichiers permanents du système.

set -u

SCRIPT_UNDER_TEST="./scripts/ban-path-explorer.sh"
TMP_DIR="/tmp/ban-path-test-$$"
TMP_LOG_DIR="$TMP_DIR/logs"
TMP_OUT_DIR="$TMP_DIR/out"
TMP_SCRIPT_COPY="$TMP_DIR/ban-path-explorer.sh"
TMP_SAFE_IPS_FILE="$TMP_DIR/safe-ips.txt"
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
FAIL_COUNT=0

TRACK_LOG_EXISTS_BEFORE="0"
TRACK_LOG_SNAPSHOT_BEFORE=""
TRACK_LOG_CONTENT_BEFORE=""

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
  awk -v track="$TMP_TRACK_LOG" -v state="$TMP_BAN_STATE" '
    /^TRACK_LOG=/ { print "TRACK_LOG=\"" track "\""; next }
    /^BAN_STATE_FILE=/ { print "BAN_STATE_FILE=\"" state "\""; next }
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
  grep -c '^IP suspecte :' "$file" 2>/dev/null || echo "0"
}

has_keywords_for_summary() {
  local file="$1"
  grep -q "Analysé" "$file" &&
  grep -Fq "fichiers error*.log" "$file" &&
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
  local out1 out2 out3 out4
  local suspect_count_2
  local suspect_count_3
  local has_bad_paths
  local has_white_ip

  if [ ! -x "$SCRIPT_UNDER_TEST" ]; then
    echo "Erreur: $SCRIPT_UNDER_TEST absent ou non exécutable."
    exit 1
  fi

  apache_dir="$(detect_apache_log_dir)"
  if [ -z "$apache_dir" ]; then
    echo "Aucun dossier de logs Apache détecté (/var/log/apache2 ou /var/log/httpd)."
    exit 0
  fi

  copy_error_logs_limited "$apache_dir"
  case "$?" in
    2)
      echo "Aucun fichier error*.log présent dans $apache_dir."
      exit 0
      ;;
    0) ;;
    *)
      echo "Erreur lors de la préparation des logs temporaires."
      exit 1
      ;;
  esac

  snapshot_track_log_before
  prepare_safe_ips_for_test
  if ! prepare_isolated_script_copy; then
    echo "Erreur lors de la préparation du script de test isolé."
    exit 1
  fi

  out1="$TMP_OUT_DIR/test1.out"
  out2="$TMP_OUT_DIR/test2.out"
  out3="$TMP_OUT_DIR/test3.out"
  out4="$TMP_OUT_DIR/test4.out"

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

  if test_track_log_not_modified; then
    TEST5_STATUS="OK"
  else
    TEST5_STATUS="FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

trap cleanup EXIT
run_tests

echo "=== TEST ban-path-explorer.sh ==="
echo "Test 1 : $TEST1_STATUS"
echo "Test 2 : $TEST2_STATUS"
echo "Test 3 : $TEST3_STATUS"
echo "Test 4 : $TEST4_STATUS"
echo "Test 5 : $TEST5_STATUS"

if [ "$FAIL_COUNT" -eq 0 ]; then
  echo "Tous les tests sont passés avec succès."
  exit 0
fi

echo "Au moins un test a échoué."
exit 1
