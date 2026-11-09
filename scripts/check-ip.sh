#!/usr/bin/env bash
#
# Indique si une IP est bloquée sur ce serveur, et pourquoi (lecture seule).
# Usage : sudo ./check-ip.sh <ip>
# Code de retour : 0 = bloquée, 1 = non bloquée, 2 = erreur ou indéterminé.
# Si l'IP n'est pas bloquée, propose un diagnostic de l'accès (lecture seule).

set -u

REQUIRE_ROOT="1"   # mis à 0 uniquement par le script de test (copie isolée)
TRACK_LOG="/var/log/ban-path-explorer.log"
BAN_STATE_FILE="/var/lib/ban-path-explorer/state"
CHAIN="BAN-PATH-EXPLORER"
# Listes de fichiers : motifs développés par le shell, y compris les journaux archivés
APACHE_ACCESS_LOGS="/var/log/apache2/*access* /var/log/httpd/*access*"
APACHE_ERROR_LOGS="/var/log/apache2/*error* /var/log/httpd/*error*"
AUTH_LOGS="/var/log/auth.log* /var/log/secure*"
CONFIG_PATHS="/etc/apache2 /etc/httpd /etc/modsecurity /etc/hosts.deny"
WEB_ROOT="/var/www"

die() { printf 'Erreur : %s\n' "$1" >&2; exit 2; }
indent() { sed 's/^/    /'; }
# Les journaux citent des données envoyées par le client : caractères de contrôle retirés avant affichage
clean() { LC_ALL=C tr -d '\000-\011\013-\037\177'; }

# search_logs "motifs" : lignes citant l'IP, de la plus ancienne à la plus récente
search_logs() {
  local files
  # shellcheck disable=SC2086  # les motifs doivent être développés
  files="$(ls -tr $1 2>/dev/null)"
  [ -n "$files" ] || return 0
  # shellcheck disable=SC2086
  zgrep -hwF "$IP" $files 2>/dev/null | clean
}

PISTES=""
piste() { PISTES="${PISTES}  - $1"$'\n'; }

diagnose() {
  local out lines status set_name

  echo
  echo "=== Diagnostic de $IP ==="

  echo "[1/6] Pare-feu"
  "$ipt" -w -S INPUT 2>/dev/null | grep -- '^-P' | indent
  out="$("$ipt" -w -S 2>/dev/null | grep -wF "$IP")"
  if [ -n "$out" ]; then
    printf '%s\n' "$out" | indent
    piste "Le pare-feu contient une règle qui cite cette IP : vérifiez ce qu'elle fait."
  fi
  # ponytail: plages listées sans calcul d'appartenance, à comparer à l'œil ; calcul CIDR si la liste devient longue
  out="$("$ipt" -w -S 2>/dev/null | grep -E -- ' -s [^ ]+/[0-9]+ .*-j (DROP|REJECT)' | grep -vE '/(32|128) ')"
  if [ -n "$out" ]; then
    echo "    Plages bloquées :"
    printf '%s\n' "$out" | indent
    piste "Des plages entières sont bloquées : vérifiez si $IP en fait partie."
  fi
  if command -v nft >/dev/null 2>&1; then
    out="$(nft list ruleset 2>/dev/null | grep -wF "$IP")"
    if [ -n "$out" ]; then
      printf '%s\n' "$out" | indent
      piste "nftables contient une règle ou un ensemble qui cite cette IP."
    fi
  fi
  if command -v ipset >/dev/null 2>&1; then
    for set_name in $(ipset list -n 2>/dev/null); do
      if ipset test "$set_name" "$IP" >/dev/null 2>&1; then
        echo "    Présente dans l'ipset : $set_name"
        piste "L'IP est dans l'ipset $set_name : vérifiez si une règle le bloque."
      fi
    done
  fi

  echo "[2/6] Route vers l'IP"
  if out="$(ip route get "$IP" 2>&1)"; then
    printf '%s\n' "$out" | head -n 1 | indent
    case "$out" in
      *blackhole*|*unreachable*|*prohibit*) piste "La route vers cette IP est bloquée : le serveur ne peut pas lui répondre." ;;
    esac
  else
    printf '%s\n' "$out" | indent
    piste "Aucune route utilisable vers cette IP (route blackhole ?) : le serveur ne peut pas lui répondre."
  fi

  echo "[3/6] Configuration (Apache, ModSecurity, hosts.deny, .htaccess)"
  # shellcheck disable=SC2086  # liste de chemins
  out="$( { grep -rIlwF "$IP" $CONFIG_PATHS 2>/dev/null; find "$WEB_ROOT" -name .htaccess -exec grep -lwF "$IP" {} + 2>/dev/null; } )"
  if [ -n "$out" ]; then
    printf '%s\n' "$out" | indent
    piste "Cette IP est citée dans la configuration : vérifiez les fichiers listés."
  else
    echo "    IP citée nulle part"
  fi

  echo "[4/6] Service web et connexions"
  out="$(ss -Hltn 2>/dev/null | grep -E ':(80|443)[[:space:]]')"
  if [ -n "$out" ]; then
    printf '%s\n' "$out" | awk '{ print $4 }' | sort -u | indent
  else
    echo "    Rien n'écoute sur les ports 80 et 443"
    piste "Aucun service n'écoute sur 80/443 : vérifiez Apache (systemctl status apache2)."
  fi
  out="$(ss -Htn 2>/dev/null | grep -wF "$IP")"
  if [ -n "$out" ]; then
    echo "    Connexions en cours :"
    printf '%s\n' "$out" | head -n 5 | indent
  else
    echo "    Aucune connexion en cours"
  fi

  echo "[5/6] Requêtes HTTP"
  lines="$(search_logs "$APACHE_ACCESS_LOGS")"
  if [ -n "$lines" ]; then
    echo "    Codes HTTP (200 dernières requêtes, nombre puis code) :"
    status="$(printf '%s\n' "$lines" | tail -n 200 | awk -F'"' 'NF >= 3 { split($3, a, " "); if (a[1] ~ /^[0-9][0-9][0-9]$/) c[a[1]]++ } END { for (s in c) print c[s], s }' | sort -rn)"
    printf '%s\n' "$status" | indent
    echo "    Dernières requêtes :"
    printf '%s\n' "$lines" | tail -n 10 | indent
    printf '%s\n' "$status" | grep -qE ' 40[13]$' && piste "Réponses 401/403 : accès refusé par Apache, .htaccess, ModSecurity ou l'application."
    printf '%s\n' "$status" | grep -qE ' 429$' && piste "Réponses 429 : limitation de débit côté application ou Apache."
    printf '%s\n' "$status" | grep -qE ' 5[0-9][0-9]$' && piste "Réponses 5xx : erreur côté serveur, voir le journal d'erreurs Apache."
  else
    echo "    Aucune requête de cette IP dans les logs d'accès"
    piste "Aucune requête dans les logs Apache : le trafic n'arrive pas (DNS, réseau ou pare-feu en amont), ou Apache journalise l'IP d'un proxy/CDN (voir la section reverse proxy du README)."
  fi
  lines="$(search_logs "$APACHE_ERROR_LOGS")"
  if [ -n "$lines" ]; then
    echo "    Dernières erreurs :"
    printf '%s\n' "$lines" | tail -n 10 | indent
    case "$lines" in
      *ModSecurity*) piste "ModSecurity a traité des requêtes de cette IP : vérifiez la règle dans le journal d'erreurs." ;;
    esac
    case "$lines" in
      *AH01630*|*AH01797*) piste "Apache refuse cette IP par configuration (Require/Deny)." ;;
    esac
  fi

  echo "[6/6] SSH"
  lines="$(search_logs "$AUTH_LOGS")"
  if [ -n "$lines" ]; then
    printf '%s\n' "$lines" | tail -n 5 | indent
    case "$lines" in
      *"Failed password"*|*"Invalid user"*) piste "Échecs de connexion SSH : identifiant, mot de passe ou clé refusés." ;;
    esac
  else
    echo "    Aucune trace"
  fi

  echo
  echo "Pistes :"
  if [ -n "$PISTES" ]; then
    printf '%s' "$PISTES"
  else
    echo "  - Rien d'anormal côté serveur : cherchez côté client, DNS ou réseau en amont."
  fi
}

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

[ "${1:-}" = "--help" ] && { sed -n 3,6p "$0" | cut -c3-; exit 0; }
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

history="$(search_logs "$TRACK_LOG*" | sort)"
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
  verdict=2
  echo "Résultat : indéterminé pour $IP (au moins une vérification a échoué)"
else
  verdict=1
  echo "Résultat : $IP n'est pas bloquée"
fi

echo
# Sans entrée disponible (cron, </dev/null), read échoue : pas de diagnostic, le code de retour reste valable
if read -r -p "Voulez-vous diagnostiquer pourquoi l'accès pose problème ? (oui/non) : " answer; then
  case "$answer" in
    [oOyY]*) diagnose ;;
  esac
fi
exit "$verdict"
