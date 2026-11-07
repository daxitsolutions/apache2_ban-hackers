#!/usr/bin/env bash
#
# Usage : ./scripts/audit-email-problems.sh DOMAINE [SELECTEUR_DKIM ...]
# Exemples :
#   ./scripts/audit-email-problems.sh daxit.be
#   ./scripts/audit-email-problems.sh example.com s1 s2      # sélecteurs DKIM supplémentaires
# Vérifie SPF, DMARC, DKIM, MTA-STS et TLS-RPT (lecture DNS uniquement).

set -u

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "-h" ] || [ "$DOMAIN" = "--help" ]; then
  sed -n '3,7p' "$0"
  [ -n "$DOMAIN" ]; exit $?
fi
shift
if ! command -v dig >/dev/null 2>&1; then
  echo "Erreur : dig est requis (sudo apt install dnsutils)" >&2
  exit 1
fi

ok()   { echo -e "${GREEN}✅ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $*${NC}"; }
bad()  { echo -e "${RED}❌ $*${NC}"; }
# Enregistrements TXT, guillemets et découpage en morceaux de 255 caractères retirés
txt()  { dig +short TXT "$1" | sed -e 's/" "//g' -e 's/"//g'; }
sep()  { echo -e "\n--------------------------------------------------\n"; }

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}    MINI-AUDIT DE SÉCURITÉ EMAIL POUR : $DOMAIN${NC}"
echo -e "${BLUE}==================================================${NC}\n"

# 1. SPF
echo -e "${BLUE}[1/5] SPF${NC}"
SPF_RECORDS="$(txt "$DOMAIN" | grep -i '^v=spf1')"
SPF_COUNT="$(printf '%s' "$SPF_RECORDS" | grep -c . )"
if [ "$SPF_COUNT" -eq 0 ]; then
  bad "Aucun enregistrement SPF : n'importe quel serveur peut envoyer au nom de @$DOMAIN."
elif [ "$SPF_COUNT" -gt 1 ]; then
  bad "$SPF_COUNT enregistrements SPF : c'est invalide (RFC 7208), le SPF est ignoré. Fusionnez-les :"
  printf '   %s\n' "$SPF_RECORDS"
else
  ok "SPF : $SPF_RECORDS"
  case "$SPF_RECORDS" in
    *-all*) ok "Politique stricte (-all)." ;;
    *~all*) warn "Politique souple (~all) : acceptable au début, passez à -all une fois les envois validés." ;;
    *\?all*) bad "Politique neutre (?all) : n'apporte aucune protection." ;;
    *+all*) bad "+all : autorise TOUS les serveurs du monde, à corriger immédiatement." ;;
    *redirect=*) ok "Politique déléguée (redirect=)." ;;
    *) bad "Pas de mécanisme 'all' final : équivaut à ?all (aucune protection)." ;;
  esac
fi
sep

# 2. DMARC
echo -e "${BLUE}[2/5] DMARC${NC}"
DMARC_RECORD="$(txt "_dmarc.$DOMAIN" | grep -i '^v=DMARC1')"
if [ -z "$DMARC_RECORD" ]; then
  bad "Aucun enregistrement DMARC : l'usurpation de @$DOMAIN n'est ni bloquée ni signalée."
else
  ok "DMARC : $DMARC_RECORD"
  case "$DMARC_RECORD" in
    *p=reject*) ok "Protection maximale (p=reject) : les faux mails sont rejetés." ;;
    *p=quarantine*) warn "Protection modérée (p=quarantine) : les faux mails vont en spam." ;;
    *p=none*) bad "Mode observation (p=none) : l'usurpation n'est pas bloquée." ;;
  esac
  [[ $DMARC_RECORD == *rua=* ]] || warn "Pas de rua= : vous ne recevez aucun rapport sur les tentatives d'usurpation."
  if [[ $DMARC_RECORD =~ pct=([0-9]+) ]] && [ "${BASH_REMATCH[1]}" -lt 100 ]; then
    warn "pct=${BASH_REMATCH[1]} : la politique ne s'applique qu'à ${BASH_REMATCH[1]} % des mails."
  fi
  [[ $DMARC_RECORD == *sp=none* ]] && warn "sp=none : les sous-domaines (x.$DOMAIN) restent usurpables."
fi
sep

# 3. DKIM
echo -e "${BLUE}[3/5] DKIM${NC}"
echo "Sélecteurs testés : courants (One.com, Microsoft 365, Google, génériques) + ceux passés en argument."
SELECTORS=(one key1 key2 20201015 20230601 selector1 selector2 google default mail smtp dkim s1 s2 k1 "$@")
FOUND_DKIM=0
for selector in "${SELECTORS[@]}"; do
  DKIM_RECORD="$(txt "${selector}._domainkey.$DOMAIN" | tr -d '[:space:]')"
  if [[ $DKIM_RECORD == *v=DKIM1* || $DKIM_RECORD == *p=* ]]; then
    if [[ $DKIM_RECORD == *"p=;"* || $DKIM_RECORD == *p= ]]; then
      warn "Sélecteur $selector : clé révoquée (p= vide)."
    else
      ok "Clé DKIM trouvée (sélecteur : $selector) : ${DKIM_RECORD:0:70}..."
      FOUND_DKIM=1
    fi
  fi
done
if [ "$FOUND_DKIM" -eq 0 ]; then
  warn "Aucune clé DKIM trouvée parmi ces sélecteurs."
  echo "-> Le sélecteur figure dans l'en-tête DKIM-Signature (s=...) d'un mail envoyé : relancez avec ce sélecteur en argument."
fi
sep

# 4. MTA-STS (chiffrement obligatoire des mails entrants)
echo -e "${BLUE}[4/5] MTA-STS${NC}"
MTASTS="$(txt "_mta-sts.$DOMAIN" | grep -i '^v=STSv1')"
if [ -n "$MTASTS" ]; then
  ok "MTA-STS : $MTASTS (politique : https://mta-sts.$DOMAIN/.well-known/mta-sts.txt)"
else
  warn "Pas de MTA-STS : un attaquant en position d'interception peut forcer la réception des mails en clair."
fi
sep

# 5. TLS-RPT (rapports d'échec TLS)
echo -e "${BLUE}[5/5] TLS-RPT${NC}"
TLSRPT="$(txt "_smtp._tls.$DOMAIN" | grep -i '^v=TLSRPTv1')"
if [ -n "$TLSRPT" ]; then
  ok "TLS-RPT : $TLSRPT"
else
  warn "Pas de TLS-RPT : vous n'êtes pas prévenu des échecs de chiffrement (utile avec MTA-STS)."
fi

echo -e "\n${BLUE}==================================================${NC}"
echo -e "${BLUE}               FIN DE L'AUDIT${NC}"
echo -e "${BLUE}==================================================${NC}"
