#!/bin/bash

# Couleurs pour l'affichage
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Pas de couleur

DOMAIN="daxit.be"

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}    MINI-AUDIT DE SÉCURITÉ EMAIL POUR : $DOMAIN   ${NC}"
echo -e "${BLUE}==================================================${NC}"
echo ""

# 1. VÉRIFICATION DU SPF
echo -e "${BLUE}[1/3] Vérification de l'enregistrement SPF...${NC}"
SPF_RECORD=$(dig +short TXT $DOMAIN | grep "v=spf1")

if [ -z "$SPF_RECORD" ]; then
    echo -e "${RED}❌ AUCUN ENREGISTREMENT SPF TROUVÉ !${NC}"
    echo -e "N'importe quel serveur peut usurper l'identité de @$DOMAIN."
else
    echo -e "${GREEN}✅ SPF trouvé :${NC} $SPF_RECORD"
    if [[ "$SPF_RECORD" == *"-all"* ]]; then
        echo -e "${GREEN}-> Politique stricte (-all) active.${NC}"
    elif [[ "$SPF_RECORD" == *"~all"* ]]; then
        echo -e "${YELLOW}-> Politique souple (~all). Recommandé au début, mais moins restrictif.${NC}"
    else
        echo -e "${RED}-> Attention: Politique obsolète ou trop permissive (?all ou +all).${NC}"
    fi
fi

echo -e "\n--------------------------------------------------\n"

# 2. VÉRIFICATION DE DMARC
echo -e "${BLUE}[2/3] Vérification de l'enregistrement DMARC...${NC}"
DMARC_RECORD=$(dig +short TXT _dmarc.$DOMAIN)

if [ -z "$DMARC_RECORD" ]; then
    echo -e "${RED}❌ AUCUN ENREGISTREMENT DMARC TROUVÉ !${NC}"
    echo -e "C'est la faille exploitée dans le mail d'exemple (dmarc=none)."
else
    echo -e "${GREEN}✅ DMARC trouvé :${NC} $DMARC_RECORD"
    if [[ "$DMARC_RECORD" == *"p=reject"* ]]; then
        echo -e "${GREEN}-> Protection maximale (p=reject) active ! Les faux mails sont bloqués.${NC}"
    elif [[ "$DMARC_RECORD" == *"p=quarantine"* ]]; then
        echo -e "${YELLOW}-> Protection modérée (p=quarantine). Les faux mails vont en spam.${NC}"
    elif [[ "$DMARC_RECORD" == *"p=none"* ]]; then
        echo -e "${RED}-> Mode observation uniquement (p=none). L'usurpation n'est pas bloquée.${NC}"
    fi
fi

echo -e "\n--------------------------------------------------\n"

# 3. VÉRIFICATION DKIM (Sélecteurs fréquents)
# 3. VÉRIFICATION DKIM (Sélecteurs ciblés et intelligents)
echo -e "${BLUE}[3/3] Vérification des clés DKIM...${NC}"
echo "Note: Le DKIM requiert de tester des 'sélecteurs' spécifiques."
echo -e "Analyse des sélecteurs officiels de votre hébergeur (One.com) et des géants du cloud :\n"

# Liste optimisée : sélecteurs One.com, Microsoft 365, Google et défauts universels
SELECTORS=(
    "one" "key1" "key2"                             # One.com standards
    "20201015" "20230601"                           # Sélecteurs historiques/temporels One.com
    "selector1" "selector2"                         # Microsoft Office 365 par défaut
    "google"                                        # Google Workspace par défaut
    "default" "mail" "smtp"                         # Génériques courants
)

FOUND_DKIM=0

for selector in "${SELECTORS[@]}"; do
    # Interrogation DNS silencieuse
    DKIM_RECORD=$(dig +short TXT ${selector}._domainkey.$DOMAIN | tr -d '"' | tr -d '[:space:]')
    
    if [ ! -z "$DKIM_RECORD" ] && [[ "$DKIM_RECORD" == *"v=DKIM1"* ]]; then
        echo -e "${GREEN}✅ Clé DKIM active trouvée !${NC} (Sélecteur: ${YELLOW}${selector}${NC})"
        # Découpage propre pour l'affichage si la clé est trop longue
        echo -e "   -> ${DKIM_RECORD:0:80}..."
        FOUND_DKIM=1
    fi
done

if [ $FOUND_DKIM -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Aucune clé DKIM publique standard n'a été détectée en surface.${NC}"
    echo "-> Si vous venez d'activer le DKIM dans le panneau One.com, l'affichage peut prendre jusqu'à 24h."
    echo "-> Si vos e-mails partent de One.com sans option activée, ils utilisent la clé globale de l'hébergeur."
fi

echo -e "\n${BLUE}==================================================${NC}"
echo -e "${BLUE}               FIN DE L'AUDIT                     ${NC}"
echo -e "${BLUE}==================================================${NC}"