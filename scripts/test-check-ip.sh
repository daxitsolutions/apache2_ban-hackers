#!/usr/bin/env bash
# Tests de check-ip.sh sur une copie isolée, avec de faux iptables, fail2ban-client et crowdsec-cli.
set -u
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0

sed -e 's/^REQUIRE_ROOT="1"/REQUIRE_ROOT="0"/' \
    -e "s#^TRACK_LOG=.*#TRACK_LOG=\"$T/ban.log\"#" \
    -e "s#^BAN_STATE_FILE=.*#BAN_STATE_FILE=\"$T/state\"#" \
    scripts/check-ip.sh > "$T/check-ip.sh"
chmod +x "$T/check-ip.sh"

cat > "$T/iptables" <<'FAKE'
#!/usr/bin/env bash
dir="$(dirname "$0")"
[ -f "$dir/ipt-broken" ] && exit 4
[ "$2" = "-S" ] && exit 0
grep -qxF -- "$*" "$dir/rules"
FAKE
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
  : > "$T/rules"; : > "$T/state"; rm -f "$T/ipt-broken"
  echo "[[]]" > "$T/f2b"
  echo "No active decisions" > "$T/cs"
  printf '[2026-11-09 10:00:00] IP suspecte: 203.0.113.10 | unique_urls=25 | paths="/a"\n' > "$T/ban.log"
  printf '[2026-11-01 10:00:00] IP suspecte: 203.0.113.20 | signature="/.env -> /.env"\n' | gzip > "$T/ban.log.1.gz"
}
ban() { echo "-w -C BAN-PATH-EXPLORER -s $1 -j DROP" >> "$T/rules"; }

# check "nom" code_attendu "texte attendu" ip
check() {
  local out rc
  out="$(PATH="$T:$PATH" "$T/check-ip.sh" "$4" 2>&1)"; rc=$?
  if [ "$rc" -eq "$2" ] && printf '%s' "$out" | grep -qF -- "$3"; then
    echo "$1 : OK"
  else
    echo "$1 : FAIL (code $rc)"; printf '%s\n' "$out"; FAIL=$((FAIL + 1))
  fi
}

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

[ "$FAIL" -eq 0 ] && echo "Tous les tests sont passés." || { echo "$FAIL test(s) en échec."; exit 1; }
