#!/usr/bin/env bash
#
# Libère une IP (ban-path-explorer, fail2ban, CrowdSec) et propose de l'ajouter à la whitelist.
# Usage : sudo ./unban-ip.sh <ip>
# Code de retour : 0 = IP libérée ou déjà libre, 2 = erreur ou libération incomplète.

set -u

REQUIRE_ROOT="1"   # mis à 0 uniquement par le script de test (copie isolée)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TRACK_LOG="/var/log/ban-path-explorer.log"
BAN_STATE_FILE="/var/lib/ban-path-explorer/state"
LOCK_DIR="/run/ban-path-explorer.lock"   # verrou partagé avec ban-path-explorer.sh
LOCK_TRIES=150                           # essais espacés de 0,2 s
CHAIN="BAN-PATH-EXPLORER"

die() { printf 'Erreur : %s\n' "$1" >&2; exit 2; }
log_track() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$TRACK_LOG" 2>/dev/null; }

is_ip() {
  case "$1" in
    *:*) [[ $1 =~ ^[0-9a-f:]+$ ]]; return ;;
  esac
  [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local o
  for o in "${BASH_REMATCH[@]:1}"; do
    [ "$((10#$o))" -le 255 ] || return 1
  done
}

# Le verrou empêche ban-path-explorer de réécrire l'état pendant qu'on le modifie
acquire_lock() {
  local i pid
  for ((i = 0; i < LOCK_TRIES; i++)); do
    if mkdir "$LOCK_DIR" 2>/dev/null; then
      printf '%s\n' "$$" > "$LOCK_DIR/pid"
      trap release_lock EXIT
      return 0
    fi
    pid="$(cat "$LOCK_DIR/pid" 2>/dev/null)"
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$LOCK_DIR/pid"
      rmdir "$LOCK_DIR" 2>/dev/null
    fi
    sleep 0.2
  done
  return 1
}

release_lock() {
  rm -f "$LOCK_DIR/pid"
  rmdir "$LOCK_DIR" 2>/dev/null
  trap - EXIT
}

in_state() {
  awk -F'|' -v ip="$IP" '$1 == ip { found = 1 } END { exit !found }' "$BAN_STATE_FILE" 2>/dev/null
}

# Remplace l'entrée par "ip|maintenant|0|maintenant" : nombre de bans 0 = libérée à la main.
# Sans cette marque, les événements encore dans la fenêtre provoqueraient un nouveau ban au cycle suivant.
mark_released() {
  local tmp now
  now="$(date +%s)"
  touch "$BAN_STATE_FILE" 2>/dev/null || return 1
  tmp="$(mktemp "$BAN_STATE_FILE.XXXXXX")" || return 1
  if awk -F'|' -v ip="$IP" '$1 != ip' "$BAN_STATE_FILE" > "$tmp" \
    && printf '%s|%s|0|%s\n' "$IP" "$now" "$now" >> "$tmp" \
    && mv -f "$tmp" "$BAN_STATE_FILE"; then
    return 0
  fi
  rm -f "$tmp"
  return 1
}

# La whitelist à modifier est celle que lit le service, où que ce script ait été copié
find_safelist() {
  local exec_path f
  exec_path="$(systemctl cat ban-path-explorer 2>/dev/null | sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' | head -n 1)"
  for f in "$(dirname "${exec_path:-/nonexistent/x}")/data/safe-ips.txt" "$SCRIPT_DIR/data/safe-ips.txt" "$SCRIPT_DIR/safe-ips.txt"; do
    if [ -f "$f" ]; then
      printf '%s\n' "$f"
      return 0
    fi
  done
  return 1
}

# ponytail: IP exacte seulement ; une IP déjà couverte par une plage CIDR est ajoutée en doublon, sans conséquence
in_safelist() {
  awk -v ip="$IP" '{ sub(/#.*/, ""); gsub(/[ \t\r]/, ""); if ($0 == ip) found = 1 } END { exit !found }' "$SAFE_IPS_FILE" 2>/dev/null
}

add_to_safelist() {
  if [ -n "$(tail -c 1 "$SAFE_IPS_FILE" 2>/dev/null)" ]; then
    echo >> "$SAFE_IPS_FILE" || return 1
  fi
  printf '%s  # ajoutée par unban-ip.sh le %s\n' "$IP" "$(date '+%Y-%m-%d')" >> "$SAFE_IPS_FILE"
}

[ "${1:-}" = "--help" ] && { sed -n 3,5p "$0" | cut -c3-; exit 0; }
[ $# -eq 1 ] || die "indiquez une IP. Usage : sudo $0 <ip>"

IP="$(printf '%s' "$1" | tr 'A-F' 'a-f')"
IP="${IP#::ffff:}"   # IPv4 mappée : bannie en IPv4 par ban-path-explorer
is_ip "$IP" || die "IP invalide : $1"
[ "$REQUIRE_ROOT" != "1" ] || [ "$(id -u)" -eq 0 ] || die "lancez ce script avec sudo : sudo $0 $1"

RELEASED=0
FAILED=0

# --- ban-path-explorer ---
case "$IP" in
  *:*) ipt=ip6tables ;;
  *) ipt=iptables ;;
esac
acquire_lock || die "ban-path-explorer est occupé ($LOCK_DIR), réessayez dans un instant"

rule_removed=0
if ! "$ipt" -w -S INPUT >/dev/null 2>&1; then
  FAILED=1
  echo "ban-path-explorer : vérification impossible ($ipt indisponible)"
elif "$ipt" -w -C "$CHAIN" -s "$IP" -j DROP >/dev/null 2>&1; then
  if "$ipt" -w -D "$CHAIN" -s "$IP" -j DROP >/dev/null 2>&1; then
    rule_removed=1
    RELEASED=1
    log_track "Déblocage manuel: $IP"
    echo "ban-path-explorer : règle de blocage retirée"
  else
    FAILED=1
    echo "ban-path-explorer : impossible de retirer la règle de blocage"
  fi
else
  echo "ban-path-explorer : aucune règle de blocage"
fi

if [ "$FAILED" -eq 0 ] && { [ "$rule_removed" -eq 1 ] || in_state; }; then
  if mark_released; then
    echo "ban-path-explorer : ban et récidives effacés de l'état"
  else
    FAILED=1
    echo "ban-path-explorer : impossible de modifier $BAN_STATE_FILE (le ban sera réappliqué)"
  fi
fi
release_lock   # avant la question : l'analyse ne doit pas attendre la réponse

# --- fail2ban : affiche la liste des jails concernées, vide si l'IP n'est pas bannie ---
if command -v fail2ban-client >/dev/null 2>&1; then
  if out="$(fail2ban-client banned "$IP" 2>/dev/null)"; then
    jails="$(printf '%s' "$out" | tr -d "[]',")"
    if [[ ! $jails =~ [A-Za-z] ]]; then
      echo "fail2ban : non bannie"
    elif fail2ban-client unban "$IP" >/dev/null 2>&1; then
      RELEASED=1
      echo "fail2ban : débannie (jails : $jails)"
    else
      FAILED=1
      echo "fail2ban : impossible de débannir (jails : $jails)"
    fi
  else
    FAILED=1
    echo "fail2ban : vérification impossible (service arrêté ?)"
  fi
fi

# --- CrowdSec ---
if command -v crowdsec-cli >/dev/null 2>&1; then
  if out="$(crowdsec-cli decisions list --ip "$IP" 2>/dev/null)"; then
    if [ -z "$out" ] || printf '%s' "$out" | grep -qi 'no active decisions'; then
      echo "CrowdSec : aucune décision"
    elif crowdsec-cli decisions delete --ip "$IP" >/dev/null 2>&1; then
      RELEASED=1
      echo "CrowdSec : décisions supprimées"
    else
      FAILED=1
      echo "CrowdSec : impossible de supprimer les décisions"
    fi
  else
    FAILED=1
    echo "CrowdSec : vérification impossible (service arrêté ?)"
  fi
fi

echo
verdict=0
if [ "$FAILED" -eq 1 ]; then
  verdict=2
  echo "Résultat : libération incomplète pour $IP"
elif [ "$RELEASED" -eq 1 ]; then
  echo "Résultat : $IP est libérée"
else
  echo "Résultat : $IP n'était pas bloquée"
fi

echo
if ! SAFE_IPS_FILE="$(find_safelist)"; then
  echo "Erreur : liste des IP saines introuvable (data/safe-ips.txt), IP non ajoutée"
  exit 2
fi
if in_safelist; then
  echo "$IP est déjà dans la liste des IP saines ($SAFE_IPS_FILE)"
  exit "$verdict"
fi

# Sans entrée disponible (cron, </dev/null), read échoue : la whitelist n'est pas modifiée
answer=""
read -r -p "Voulez-vous ajouter cette IP à la liste des IP saines ? (oui/non) : " answer
case "$answer" in
  [oOyY]*)
    if add_to_safelist; then
      log_track "Whitelist: $IP ajoutée par unban-ip.sh"
      echo "$IP ajoutée à $SAFE_IPS_FILE"
      if command -v fail2ban-client >/dev/null 2>&1 || command -v crowdsec-cli >/dev/null 2>&1; then
        echo "fail2ban et CrowdSec ont leur propre whitelist : ajoutez-y aussi cette IP si besoin (voir le README)."
      fi
    else
      verdict=2
      echo "Erreur : impossible d'écrire dans $SAFE_IPS_FILE"
    fi
    ;;
  *)
    echo "IP non ajoutée : une nouvelle requête suspecte de $IP déclenchera un nouveau ban."
    ;;
esac
exit "$verdict"
