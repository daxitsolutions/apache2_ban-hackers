#!/usr/bin/env bash
#
# Usage : ./scripts/test-ban-path-explorer.sh
# Script de test pour vérifier le comportement de ban-path-explorer.sh
# à partir des vrais fichiers error*.log Apache copiés en zone temporaire.

set -u

SCRIPT_UNDER_TEST="./scripts/ban-path-explorer.sh"
TMP_DIR="/tmp/ban-path-test-$$"
TMP_LOG_DIR="$TMP_DIR/logs"
TMP_OUT_DIR="$TMP_DIR/out"
SAFE_IPS_FILE="./scripts/safe-ips.txt"
TRACK_LOG="/var/log/ban-path-explorer.log"
APACHE_DIR_PRIMARY="/var/log/apache2"
APACHE_DIR_FALLBACK="/var/log/httpd"

TEST1_STATUS="FAIL"
TEST2_STATUS="FAIL"
TEST3_STATUS="FAIL"
TEST4_STATUS="FAIL"
TEST5_STATUS="FAIL"

FAIL_COUNT=0

ORIG_SAFE_IPS_EXISTS="0"
ORIG_SAFE_IPS_CONTENT=""

TRACK_LOG_EXISTS_BEFORE="0"
TRACK_LOG_SNAPSHOT_BEFORE=""
TRACK_LOG_CONTENT_BEFORE=""

cleanup() {
  if [ "$ORIG_SAFE_IPS_EXISTS" = "1" ]; then
    cat <<EOF > "$SAFE_IPS_FILE"
$ORIG_SAFE_IPS_CONTENT
EOF
  else
    rm -f -- "$SAFE_IPS_FILE" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$TMP_DIR" >/dev/null 2>&1 || true
}

prepare_safe_ips_backup() {
  if [ -f "$SAFE_IPS_FILE" ]; then
    ORIG_SAFE_IPS_EXISTS="1"
    ORIG_SAFE_IPS_CONTENT="$(cat "$SAFE_IPS_FILE")"
  else
    ORIG_SAFE_IPS_EXISTS="0"
    ORIG_SAFE_IPS_CONTENT=""
  fi
}

prepare_track_log_snapshot_before() {
  if [ -e "$TRACK_LOG" ]; then
    TRACK_LOG_EXISTS_BEFORE="1"
    TRACK_LOG_SNAPSHOT_BEFORE="$(ls -ld -- "$TRACK_LOG" 2>/dev/null || echo "")"
    TRACK_LOG_CONTENT_BEFORE="$(cat "$TRACK_LOG" 2>/dev/null || echo "")"
  else
    TRACK_LOG_EXISTS_BEFORE="0"
    TRACK_LOG_SNAPSHOT_BEFORE=""
    TRACK_LOG_CONTENT_BEFORE=""
  fi
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

copy_error_logs() {
  local src_dir="$1"
  local copied="0"
  local f
  mkdir -p "$TMP_LOG_DIR" "$TMP_OUT_DIR" || return 1
  for f in "$src_dir"/error*.log; do
    [ -f "$f" ] || continue
    cp -- "$f" "$TMP_LOG_DIR/" || return 1
    copied="1"
  done
  if [ "$copied" = "1" ]; then
    return 0
  fi
  return 2
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

run_tests() {
  local apache_dir
  local out1_quiet out1_visible out2 out3 out4
  local suspect_count_2
  local suspect_count_3
  local suspect_count_4
  local track_log_exists_after
  local track_log_snapshot_after
  local track_log_content_after

  if [ ! -x "$SCRIPT_UNDER_TEST" ]; then
    echo "Erreur: $SCRIPT_UNDER_TEST absent ou non exécutable."
    exit 1
  fi

  apache_dir="$(detect_apache_log_dir)"
  if [ -z "$apache_dir" ]; then
    echo "Aucun dossier de logs Apache détecté (/var/log/apache2 ou /var/log/httpd)."
    exit 0
  fi

  copy_error_logs "$apache_dir"
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

  prepare_safe_ips_backup
  prepare_track_log_snapshot_before

  out1_quiet="$TMP_OUT_DIR/test1_quiet.out"
  out1_visible="$TMP_OUT_DIR/test1_visible.out"
  out2="$TMP_OUT_DIR/test2.out"
  out3="$TMP_OUT_DIR/test3.out"
  out4="$TMP_OUT_DIR/test4.out"

  "$SCRIPT_UNDER_TEST" --log-dir "$TMP_LOG_DIR" --quiet > "$out1_quiet" 2>&1
  if [ "$?" -eq 0 ]; then
    "$SCRIPT_UNDER_TEST" --log-dir "$TMP_LOG_DIR" > "$out1_visible" 2>&1
    if [ "$?" -eq 0 ] && has_keywords_for_summary "$out1_visible"; then
      TEST1_STATUS="OK"
    else
      TEST1_STATUS="FAIL"
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
  else
    TEST1_STATUS="FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi

  "$SCRIPT_UNDER_TEST" --log-dir "$TMP_LOG_DIR" --threshold 5 --window 10 > "$out2" 2>&1
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

  "$SCRIPT_UNDER_TEST" --log-dir "$TMP_LOG_DIR" --threshold 5 --window 10 --ignore-paths "favicon.ico,robots.txt" > "$out3" 2>&1
  if [ "$?" -eq 0 ]; then
    if grep -E '^Chemins :' "$out3" | grep -Eq 'favicon\.ico|robots\.txt'; then
      TEST3_STATUS="FAIL"
      FAIL_COUNT=$((FAIL_COUNT + 1))
    else
      TEST3_STATUS="OK"
    fi
  else
    TEST3_STATUS="FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi

  cat <<EOF > "$SAFE_IPS_FILE"
127.0.0.1
::1
EOF
  "$SCRIPT_UNDER_TEST" --log-dir "$TMP_LOG_DIR" --threshold 1 --window 60 > "$out4" 2>&1
  if [ "$?" -eq 0 ]; then
    suspect_count_4="$(grep -c '^IP suspecte : 127\.0\.0\.1$' "$out4" 2>/dev/null || echo "0")"
    if [ "$suspect_count_4" = "0" ]; then
      TEST4_STATUS="OK"
    else
      TEST4_STATUS="FAIL"
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
  else
    TEST4_STATUS="FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi

  if [ -e "$TRACK_LOG" ]; then
    track_log_exists_after="1"
    track_log_snapshot_after="$(ls -ld -- "$TRACK_LOG" 2>/dev/null || echo "")"
    track_log_content_after="$(cat "$TRACK_LOG" 2>/dev/null || echo "")"
  else
    track_log_exists_after="0"
    track_log_snapshot_after=""
    track_log_content_after=""
  fi

  if [ "$TRACK_LOG_EXISTS_BEFORE" = "0" ] && [ "$track_log_exists_after" = "0" ]; then
    TEST5_STATUS="OK"
  elif [ "$TRACK_LOG_EXISTS_BEFORE" = "1" ] && [ "$track_log_exists_after" = "1" ]; then
    if [ "$TRACK_LOG_SNAPSHOT_BEFORE" = "$track_log_snapshot_after" ] && [ "$TRACK_LOG_CONTENT_BEFORE" = "$track_log_content_after" ]; then
      TEST5_STATUS="OK"
    else
      TEST5_STATUS="FAIL"
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
  else
    TEST5_STATUS="FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi

  suspect_count_3="$(count_suspects_in_output "$out3")"
  case "$suspect_count_3" in
    ''|*[!0-9]*) ;;
    *) ;;
  esac
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
