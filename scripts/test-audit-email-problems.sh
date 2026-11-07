#!/usr/bin/env bash
# Tests de audit-email-problems.sh avec un faux "dig" (aucune requête DNS réelle).
set -u
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0

# check "nom" "réponses DNS (nom|valeur par ligne)" "texte attendu dans la sortie"
check() {
  printf '%s\n' "$2" > "$T/records"
  cat > "$T/dig" <<'DIG'
#!/usr/bin/env bash
name="${*: -1}"
awk -F'|' -v n="$name" '$1 == n { print "\"" $2 "\"" }' "$(dirname "$0")/records"
DIG
  chmod +x "$T/dig"
  if PATH="$T:$PATH" ./scripts/audit-email-problems.sh ex.test | sed 's/\x1b\[[0-9;]*m//g' | grep -qF -- "$3"; then
    echo "$1 : OK"
  else
    echo "$1 : FAIL"; FAIL=$((FAIL + 1))
  fi
}

check "SPF absent"        "x|y"                                         "Aucun enregistrement SPF"
check "SPF double"        $'ex.test|v=spf1 -all\nex.test|v=spf1 ~all'   "2 enregistrements SPF"
check "SPF +all"          "ex.test|v=spf1 +all"                         "+all : autorise TOUS"
check "SPF sans all"      "ex.test|v=spf1 include:x.test"               "Pas de mécanisme 'all'"
check "SPF strict"        "ex.test|v=spf1 -all"                         "Politique stricte"
check "DMARC sans rua"    "_dmarc.ex.test|v=DMARC1; p=reject"           "Pas de rua="
check "DMARC pct"         "_dmarc.ex.test|v=DMARC1; p=reject; pct=20; rua=mailto:a@ex.test" "pct=20"
check "DKIM sélecteur arg" "s9._domainkey.ex.test|v=DKIM1; k=rsa; p=MIIBIjAN" "Aucune clé DKIM"
check "MTA-STS présent"   "_mta-sts.ex.test|v=STSv1; id=1"              "MTA-STS : v=STSv1"

# sélecteur passé en argument
printf 's9._domainkey.ex.test|v=DKIM1; k=rsa; p=MIIBIjAN\n' > "$T/records"
if PATH="$T:$PATH" ./scripts/audit-email-problems.sh ex.test s9 | grep -q "sélecteur : s9"; then echo "DKIM sélecteur en argument : OK"; else echo "DKIM sélecteur en argument : FAIL"; FAIL=$((FAIL + 1)); fi
if ./scripts/audit-email-problems.sh >/dev/null 2>&1; then echo "Sans domaine = erreur : FAIL"; FAIL=$((FAIL + 1)); else echo "Sans domaine = erreur : OK"; fi

[ "$FAIL" -eq 0 ] && echo "Tous les tests sont passés." || { echo "$FAIL test(s) en échec."; exit 1; }
