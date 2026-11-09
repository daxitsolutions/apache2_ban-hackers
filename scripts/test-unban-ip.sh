#!/usr/bin/env bash
# Tests de unban-ip.sh sur une copie isolée, avec de faux iptables, fail2ban-client et crowdsec-cli.
set -u
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0
IP_T=203.0.113.30

mkdir -p "$T/data" "$T/bin"
sed -e 's/^REQUIRE_ROOT="1"/REQUIRE_ROOT="0"/' \
    -e "s#^TRACK_LOG=.*#TRACK_LOG=\"$T/ban.log\"#" \
    -e "s#^BAN_STATE_FILE=.*#BAN_STATE_FILE=\"$T/state\"#" \
    -e "s#^LOCK_DIR=.*#LOCK_DIR=\"$T/lock\"#" \
    -e 's/^LOCK_TRIES=.*/LOCK_TRIES=3/' \
    scripts/unban-ip.sh > "$T/unban-ip.sh"
chmod +x "$T/unban-ip.sh"

cat > "$T/bin/iptables" <<'FAKE'
#!/usr/bin/env bash
dir="$(dirname "$0")/.."
[ -f "$dir/ipt-broken" ] && exit 4
[ "$2" = "-S" ] && exit 0
rule="${*:3}"
case "$2" in
  -C) grep -qxF -- "$rule" "$dir/rules" ;;
  -D) [ ! -f "$dir/ipt-nodel" ] || exit 1
      grep -vxF -- "$rule" "$dir/rules" > "$dir/rules.new"; mv "$dir/rules.new" "$dir/rules" ;;
esac
FAKE
cat > "$T/bin/fail2ban-client" <<'FAKE'
#!/usr/bin/env bash
dir="$(dirname "$0")/.."
if [ "$1" = "banned" ]; then cat "$dir/f2b"; else echo "$*" >> "$dir/called"; fi
FAKE
cat > "$T/bin/crowdsec-cli" <<'FAKE'
#!/usr/bin/env bash
dir="$(dirname "$0")/.."
if [ "$2" = "list" ]; then cat "$dir/cs"; else echo "$*" >> "$dir/called"; fi
FAKE
cp "$T/bin/iptables" "$T/bin/ip6tables"
chmod +x "$T"/bin/*

reset() {
  : > "$T/rules"; : > "$T/state"; : > "$T/ban.log"; : > "$T/called"
  rm -f "$T/ipt-broken" "$T/ipt-nodel"; rm -rf "$T/lock"
  printf '127.0.0.1\n' > "$T/data/safe-ips.txt"
  echo "[[]]" > "$T/f2b"
  echo "No active decisions" > "$T/cs"
}
ban() { echo "BAN-PATH-EXPLORER -s $1 -j DROP" >> "$T/rules"; echo "$1|$(( $(date +%s) + 3600 ))|3|1" >> "$T/state"; }

# run ip "réponse" : renseigne OUT et RC
run() {
  OUT="$(printf '%s' "$2" | PATH="$T/bin:$PATH" "$T/unban-ip.sh" "$1" 2>&1)"; RC=$?
}
ok() { echo "$1 : OK"; }
ko() { echo "$1 : FAIL (code $RC)"; printf '%s\n' "$OUT"; FAIL=$((FAIL + 1)); }
# expect "nom" commande... : réussit si la commande réussit
expect() { local n="$1"; shift; if "$@"; then ok "$n"; else ko "$n"; fi; }
said() { printf '%s' "$OUT" | grep -qF -- "$1"; }
safelisted() { grep -q "^$1 " "$T/data/safe-ips.txt"; }
no_rule() { ! grep -qF -- " $1 " "$T/rules"; }
marked() { grep -q "^$1|[0-9]*|0|[0-9]*$" "$T/state"; }
rc_is() { [ "$RC" -eq "$1" ]; }

reset; ban $IP_T; run $IP_T $'oui\n'
expect "Bloquée : code 0"              rc_is 0
expect "Bloquée : règle retirée"       no_rule $IP_T
expect "Bloquée : état marqué libéré"  marked $IP_T
expect "Oui : ajoutée à la whitelist"  safelisted $IP_T
expect "Journal : déblocage"           grep -qF "Déblocage manuel: $IP_T" "$T/ban.log"
expect "Journal : whitelist"           grep -qF "Whitelist: $IP_T" "$T/ban.log"
expect "Verrou libéré"                 test ! -d "$T/lock"

reset; ban $IP_T; ban 203.0.113.31; run $IP_T $'non\n'
expect "Non : règle retirée"           no_rule $IP_T
expect "Non : pas de whitelist"        bash -c "! grep -q $IP_T '$T/data/safe-ips.txt'"
expect "Non : avertissement"           said "nouveau ban"
expect "Autre IP : règle conservée"    grep -qF " 203.0.113.31 " "$T/rules"
expect "Autre IP : état conservé"      grep -q "^203.0.113.31|[0-9]*|3|1$" "$T/state"

reset; ban $IP_T; run $IP_T ""
expect "Sans entrée : code 0"          rc_is 0
expect "Sans entrée : pas de whitelist" bash -c "! grep -q $IP_T '$T/data/safe-ips.txt'"

reset; run $IP_T $'non\n'
expect "Non bloquée : code 0"          rc_is 0
expect "Non bloquée : message"         said "n'était pas bloquée"
expect "Non bloquée : état intact"     test ! -s "$T/state"

reset; echo "$IP_T|1000|2|1" > "$T/state"; run $IP_T $'non\n'
expect "Ban expiré : récidives effacées" marked $IP_T

reset; printf '%s  # admin\n' $IP_T >> "$T/data/safe-ips.txt"; run $IP_T $'oui\n'
expect "Déjà whitelistée : message"    said "déjà dans la liste"
expect "Déjà whitelistée : pas de doublon" test "$(grep -c $IP_T "$T/data/safe-ips.txt")" -eq 1

reset; printf '127.0.0.1' > "$T/data/safe-ips.txt"; run $IP_T $'oui\n'
expect "Fichier sans fin de ligne"     grep -qx "127.0.0.1" "$T/data/safe-ips.txt"
expect "Fichier sans fin de ligne : ajout" safelisted $IP_T

reset; ban $IP_T; mkdir "$T/lock"; echo $$ > "$T/lock/pid"; run $IP_T $'non\n'
expect "Verrou occupé : erreur"        rc_is 2
expect "Verrou occupé : règle intacte" grep -qF " $IP_T " "$T/rules"
expect "Verrou occupé : verrou conservé" test -d "$T/lock"

reset; ban $IP_T; mkdir "$T/lock"; echo 99999 > "$T/lock/pid"; run $IP_T $'non\n'
expect "Verrou périmé : repris"        no_rule $IP_T

reset; ban $IP_T
( sleep 1; if [ -d "$T/lock" ]; then touch "$T/held"; fi; echo non ) | PATH="$T/bin:$PATH" "$T/unban-ip.sh" $IP_T >/dev/null 2>&1
OUT=""; RC=0
expect "Verrou libéré avant la question" test ! -f "$T/held"

reset; ban $IP_T; touch "$T/ipt-nodel"; run $IP_T $'non\n'
expect "Retrait impossible : erreur"   rc_is 2
expect "Retrait impossible : état intact" bash -c "! grep -q '|0|' '$T/state'"

reset; touch "$T/ipt-broken"; run $IP_T $'non\n'
expect "Pare-feu illisible : erreur"   rc_is 2

reset; echo "[['sshd']]" > "$T/f2b"; run $IP_T $'non\n'
expect "fail2ban : débannie"           grep -qx "unban $IP_T" "$T/called"
expect "fail2ban : code 0"             rc_is 0

reset; echo "ban $IP_T crowdsecurity/ssh-bf" > "$T/cs"; run $IP_T $'non\n'
expect "CrowdSec : décision supprimée" grep -qx "decisions delete --ip $IP_T" "$T/called"

reset; ban 203.0.113.40; run ::ffff:203.0.113.40 $'non\n'
expect "IPv4 mappée"                   no_rule 203.0.113.40

reset; ban 2001:db8::1; run 2001:DB8::1 $'oui\n'
expect "IPv6 en majuscules"            no_rule 2001:db8::1
expect "IPv6 en majuscules : whitelist" safelisted 2001:db8::1

reset; for bad in 203.0.113.999 '1.2.3.4;id' 203.0.113.0/24; do
  run "$bad" $'oui\n'
  expect "IP invalide refusée ($bad)"  rc_is 2
done
expect "IP invalide : whitelist intacte" test "$(grep -c . "$T/data/safe-ips.txt")" -eq 1

[ "$FAIL" -eq 0 ] && echo "Tous les tests sont passés." || { echo "$FAIL test(s) en échec."; exit 1; }
