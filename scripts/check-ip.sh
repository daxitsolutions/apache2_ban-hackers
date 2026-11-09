#!/usr/bin/env bash
#
# Indique si une IP est bloquée sur ce serveur, et pourquoi (lecture seule).
# Usage : sudo ./check-ip.sh <ip>
# Code de retour : 0 = bloquée, 1 = non bloquée, 2 = erreur ou indéterminé.

set -u

REQUIRE_ROOT="1"   # mis à 0 uniquement par le script de test (copie isolée)
TRACK_LOG="/var/log/ban-path-explorer.log"
BAN_STATE_FILE="/var/lib/ban-path-explorer/state"
CHAIN="BAN-PATH-EXPLORER"

die() { printf 'Erreur : %s\n' "$1" >&2; exit 2; }

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

format_date() {
  date -d "@$1" '+%Y-%m-%d %H:%M' 2>/dev/null || date -r "$1" '+%Y-%m-%d %H:%M'
}

[ "${1:-}" = "--help" ] && { sed -n 3,5p "$0" | cut -c3-; exit 0; }
[ $# -eq 1 ] || die "indiquez une IP. Usage : sudo $0 <ip>"

IP="$(printf '%s' "$1" | tr 'A-F' 'a-f')"
IP="${IP#::ffff:}"   # IPv4 mappée : bannie en IPv4 par ban-path-explorer
is_ip "$IP" || die "IP invalide : $1"
[ "$REQUIRE_ROOT" != "1" ] || [ "$(id -u)" -eq 0 ] || die "lancez ce script avec sudo : sudo $0 $1"

BLOCKED=0
UNKNOWN=0

# --- ban-path-explorer ---
case "$IP" in
  *:*) ipt=ip6tables ;;
  *) ipt=iptables ;;
esac
# INPUT existe toujours : si elle est illisible, c'est le pare-feu qui est en cause, pas l'absence de chaîne
if ! "$ipt" -w -S INPUT >/dev/null 2>&1; then
  UNKNOWN=1
  echo "ban-path-explorer : vérification impossible ($ipt indisponible)"
elif "$ipt" -w -C "$CHAIN" -s "$IP" -j DROP >/dev/null 2>&1; then
  BLOCKED=1
  echo "ban-path-explorer : BLOQUÉE (règle DROP dans la chaîne $CHAIN)"
else
  echo "ban-path-explorer : aucune règle de blocage"
fi

state="$(awk -F'|' -v ip="$IP" '$1 == ip { line = $2 " " $3 } END { print line }' "$BAN_STATE_FILE" 2>/dev/null)"
read -r exp count <<< "$state"
if [[ ${exp:-} =~ ^[0-9]+$ ]]; then
  if [ "$exp" -gt "$(date +%s)" ]; then
    echo "  Ban n°${count:-1}, jusqu'à $(format_date "$exp")"
  else
    echo "  Dernier ban (n°${count:-1}) expiré le $(format_date "$exp")"
  fi
fi

# Le journal cite des URLs envoyées par l'attaquant : caractères de contrôle retirés avant affichage
history="$(zgrep -hwF "$IP" "$TRACK_LOG"* 2>/dev/null | sort | LC_ALL=C tr -d '\000-\011\013-\037\177')"
reason="$(printf '%s\n' "$history" | grep -F "IP suspecte: $IP |" | tail -n 1)"
case "$reason" in
  *unique_urls=*) echo "  Dernière raison : scan ou brute force | ${reason#*| }" ;;
  *signature=*) echo "  Dernière raison : signature d'attaque ou blocage ModSecurity | ${reason#*| }" ;;
esac
if [ -n "$history" ]; then
  echo "  Journal (20 dernières lignes) :"
  printf '%s\n' "$history" | tail -n 20 | sed 's/^/    /'
else
  echo "  Aucune trace dans le journal"
fi

# --- fail2ban : affiche la liste des jails concernées, vide si l'IP n'est pas bannie ---
if command -v fail2ban-client >/dev/null 2>&1; then
  if out="$(fail2ban-client banned "$IP" 2>/dev/null)"; then
    jails="$(printf '%s' "$out" | tr -d "[]',")"
    if [[ $jails =~ [A-Za-z] ]]; then
      BLOCKED=1
      echo "fail2ban : BLOQUÉE (jails : $jails)"
    else
      echo "fail2ban : non bannie"
    fi
  else
    UNKNOWN=1
    echo "fail2ban : vérification impossible (service arrêté ?)"
  fi
fi

# --- CrowdSec ---
if command -v crowdsec-cli >/dev/null 2>&1; then
  if out="$(crowdsec-cli decisions list --ip "$IP" 2>/dev/null)"; then
    if [ -z "$out" ] || printf '%s' "$out" | grep -qi 'no active decisions'; then
      echo "CrowdSec : aucune décision"
    else
      BLOCKED=1
      echo "CrowdSec : BLOQUÉE"
      printf '%s\n' "$out"
    fi
  else
    UNKNOWN=1
    echo "CrowdSec : vérification impossible (service arrêté ?)"
  fi
fi

echo
if [ "$BLOCKED" -eq 1 ]; then
  echo "Résultat : $IP est BLOQUÉE"
  exit 0
fi
if [ "$UNKNOWN" -eq 1 ]; then
  echo "Résultat : indéterminé pour $IP (au moins une vérification a échoué)"
  exit 2
fi
echo "Résultat : $IP n'est pas bloquée"
exit 1
