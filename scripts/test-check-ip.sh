#!/usr/bin/env bash
# Tests de check-ip.sh sur une copie isolée, avec de faux iptables, fail2ban-client et crowdsec-cli.
set -u
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0

sed -e 's/^REQUIRE_ROOT="1"/REQUIRE_ROOT="0"/' \
    -e "s#^TRACK_LOG=.*#TRACK_LOG=\"$T/ban.log\"#" \
    -e "s#^BAN_STATE_FILE=.*#BAN_STATE_FILE=\"$T/state\"#" \
    -e "s#^APACHE_ACCESS_LOGS=.*#APACHE_ACCESS_LOGS=\"$T/access*\"#" \
    -e "s#^APACHE_ERROR_LOGS=.*#APACHE_ERROR_LOGS=\"$T/error*\"#" \
    -e "s#^AUTH_LOGS=.*#AUTH_LOGS=\"$T/auth*\"#" \
    -e "s#^CONFIG_PATHS=.*#CONFIG_PATHS=\"$T/conf\"#" \
    -e "s#^WEB_ROOT=.*#WEB_ROOT=\"$T/www\"#" \
    scripts/check-ip.sh > "$T/check-ip.sh"
chmod +x "$T/check-ip.sh"

cat > "$T/iptables" <<'FAKE'
#!/usr/bin/env bash
dir="$(dirname "$0")"
[ -f "$dir/ipt-broken" ] && exit 4
[ "$2" = "-S" ] && { cat "$dir/fw"; exit 0; }
grep -qxF -- "$*" "$dir/rules"
FAKE
cat > "$T/ss" <<'FAKE'
#!/usr/bin/env bash
dir="$(dirname "$0")"
if [ "$1" = "-Hltn" ]; then cat "$dir/listen"; else cat "$dir/conns"; fi
FAKE
cat > "$T/ip" <<'FAKE'
#!/usr/bin/env bash
dir="$(dirname "$0")"
cat "$dir/route"
[ ! -f "$dir/route-fails" ]
FAKE
printf '#!/usr/bin/env bash\nexit 0\n' > "$T/nft"
printf '#!/usr/bin/env bash\nexit 0\n' > "$T/ipset"
chmod +x "$T/ss" "$T/ip" "$T/nft" "$T/ipset"
cat > "$T/fail2ban-client" <<'FAKE'
#!/usr/bin/env bash
cat "$(dirname "$0")/f2b"
FAKE
cat > "$T/crowdsec-cli" <<'FAKE'
#!/usr/bin/env bash
cat "$(dirname "$0")/cs"
FAKE
cp "$T/iptables" "$T/ip6tables"
chmod +x "$T/iptables" "$T/ip6tables" "$T/fail2ban-client" "$T/crowdsec-cli"

FUTURE=$(( $(date +%s) + 3600 ))
reset() {
  : > "$T/rules"; : > "$T/state"; rm -f "$T/ipt-broken" "$T/route-fails" "$T"/access* "$T"/error* "$T"/auth*
  rm -rf "$T/conf" "$T/www"; mkdir -p "$T/conf" "$T/www"
  echo "-P INPUT ACCEPT" > "$T/fw"
  echo "LISTEN 0 511 *:443 *:*" > "$T/listen"
  : > "$T/conns"
  echo "203.0.113.30 via 192.0.2.1 dev eth0" > "$T/route"
  echo "[[]]" > "$T/f2b"
  echo "No active decisions" > "$T/cs"
  printf '[2026-11-09 10:00:00] IP suspecte: 203.0.113.10 | unique_urls=25 | paths="/a"\n' > "$T/ban.log"
  printf '[2026-11-01 10:00:00] IP suspecte: 203.0.113.20 | signature="/.env -> /.env"\n' | gzip > "$T/ban.log.1.gz"
}
ban() { echo "-w -C BAN-PATH-EXPLORER -s $1 -j DROP" >> "$T/rules"; }

# check "nom" code_attendu "texte attendu" ip
check() {
  local out rc
  out="$(printf '%s' "${ANSWER:-}" | PATH="$T:$PATH" "$T/check-ip.sh" "$4" 2>&1)"; rc=$?
  if [ "$rc" -eq "$2" ] && printf '%s' "$out" | grep -qF -- "$3"; then
    echo "$1 : OK"
  else
    echo "$1 : FAIL (code $rc)"; printf '%s\n' "$out"; FAIL=$((FAIL + 1))
  fi
}

# refute "nom" "texte qui ne doit pas apparaître" ip
refute() {
  if printf '%s' "${ANSWER:-}" | PATH="$T:$PATH" "$T/check-ip.sh" "$3" 2>&1 | grep -qF -- "$2"; then
    echo "$1 : FAIL"; FAIL=$((FAIL + 1))
  else
    echo "$1 : OK"
  fi
}

access() { echo "$IP_T - - [09/Nov/2026:10:00:00 +0100] \"GET / HTTP/1.1\" $1 12 \"-\" \"curl\"" >> "$T/access.log"; }
IP_T=203.0.113.30

reset; ban 203.0.113.10; echo "203.0.113.10|$FUTURE|2|1" > "$T/state"
check "Ban actif : durée"       0 "Ban n°2, jusqu'à"       203.0.113.10
check "Ban actif : raison scan" 0 "scan ou brute force"    203.0.113.10
check "Résultat bloquée"        0 "est BLOQUÉE"            203.0.113.10
check "IP voisine non confondue" 1 "Aucune trace"          203.0.113.1

reset; ban 203.0.113.20
check "Raison dans journal archivé" 0 "signature d'attaque" 203.0.113.20
check "IPv4 mappée"             0 "est BLOQUÉE"            ::ffff:203.0.113.20

reset; ban 2001:db8::1
check "IPv6 en majuscules"      0 "est BLOQUÉE"            2001:DB8::1

reset; echo "203.0.113.10|1000|1|1" > "$T/state"
check "Ban expiré"              1 "expiré le"              203.0.113.10
check "Non bloquée"             1 "n'est pas bloquée"      203.0.113.10

reset; echo "[['sshd', 'recidive']]" > "$T/f2b"
check "fail2ban"                0 "jails : sshd recidive"  203.0.113.30

reset; echo "ban 203.0.113.30 crowdsecurity/ssh-bf" > "$T/cs"
check "CrowdSec"                0 "crowdsecurity/ssh-bf"   203.0.113.30

reset; touch "$T/ipt-broken"
check "Pare-feu illisible = indéterminé" 2 "indéterminé"   203.0.113.30

reset
check "Octet invalide"          2 "IP invalide"            203.0.113.999
check "Injection refusée"       2 "IP invalide"            '1.2.3.4;id'
check "Plage refusée"           2 "IP invalide"            203.0.113.0/24

# Diagnostic : le code de retour reste celui du verdict
ANSWER=$'non\n'; reset
refute "Réponse non : pas de diagnostic" "=== Diagnostic" $IP_T
ANSWER=""; reset
refute "Sans entrée : pas de diagnostic" "=== Diagnostic" $IP_T
ANSWER=$'oui\n'; reset; ban $IP_T
refute "IP bloquée : pas de question" "=== Diagnostic" $IP_T

reset
check "Oui : diagnostic, code conservé" 1 "=== Diagnostic"  $IP_T
check "Pas de requête"          1 "le trafic n'arrive pas"  $IP_T
reset; access 200
check "Rien d'anormal"          1 "Rien d'anormal"          $IP_T
refute "Pas de fausse piste 403" "accès refusé" $IP_T
reset; access 403; access 403; access 200
check "Codes comptés"           1 "2 403"                   $IP_T
check "Piste 403"               1 "accès refusé"            $IP_T
reset; access 503
check "Piste 5xx"               1 "erreur côté serveur"     $IP_T
reset; echo "[client $IP_T:5000] AH01630: client denied by server configuration" > "$T/error.log"
check "Piste Require"           1 "par configuration"       $IP_T
reset; echo "sshd: Failed password for root from $IP_T port 22" > "$T/auth.log"
check "Piste SSH"               1 "Échecs de connexion SSH" $IP_T
reset; echo "-A INPUT -s $IP_T/32 -j DROP" >> "$T/fw"
check "Règle pare-feu hors chaîne" 1 "règle qui cite"       $IP_T
reset; echo "-A INPUT -s 203.0.0.0/16 -j DROP" >> "$T/fw"
check "Plage bloquée listée"    1 "203.0.0.0/16"            $IP_T
reset; echo "Require not ip $IP_T" > "$T/conf/site.conf"
check "IP dans la config"       1 "site.conf"               $IP_T
reset; echo "Deny from $IP_T" > "$T/www/.htaccess"
check "IP dans .htaccess"       1 ".htaccess"               $IP_T
reset; echo "RTNETLINK answers: Invalid argument" > "$T/route"; touch "$T/route-fails"
check "Route blackhole"         1 "Aucune route"            $IP_T
reset; : > "$T/listen"
check "Apache arrêté"           1 "Aucun service"           $IP_T
reset; touch "$T/ipt-broken"
check "Indéterminé : diagnostic, code conservé" 2 "=== Diagnostic" $IP_T
ANSWER=""

[ "$FAIL" -eq 0 ] && echo "Tous les tests sont passés." || { echo "$FAIL test(s) en échec."; exit 1; }
