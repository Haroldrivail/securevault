#!/bin/bash

# Script de migration des secrets depuis un fichier .env vers SecureVault
# Usage: ./migrate-from-dotenv.sh [fichier.env]

set -e

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ENV_FILE="${1:-.env}"

echo -e "${GREEN}=== Migration depuis .env vers SecureVault ===${NC}"
echo ""

# Vérifier que le fichier .env existe
if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}Erreur : fichier '$ENV_FILE' introuvable${NC}"
    echo "Usage: $0 [fichier.env]"
    exit 1
fi

# Vérifier que vault est installé
if ! command -v vault &> /dev/null; then
    echo -e "${RED}Erreur : commande 'vault' introuvable${NC}"
    echo "Installez SecureVault d'abord : cargo install --path vault-cli"
    exit 1
fi

# Demander le chemin du vault (optionnel)
read -p "Chemin du vault (Entrée pour défaut) : " VAULT_PATH
if [ -n "$VAULT_PATH" ]; then
    VAULT_ARG="--vault $VAULT_PATH"
else
    VAULT_ARG=""
fi

# Initialiser le vault si nécessaire
if [ -n "$VAULT_PATH" ] && [ ! -f "$VAULT_PATH" ]; then
    echo -e "${YELLOW}Le vault n'existe pas encore. Initialisation...${NC}"
    vault $VAULT_ARG init
    echo ""
elif [ -z "$VAULT_PATH" ] && [ ! -f ~/.config/securevault/vault.db ]; then
    echo -e "${YELLOW}Le vault n'existe pas encore. Initialisation...${NC}"
    vault init
    echo ""
fi

# Compter les secrets à migrer
TOTAL=$(grep -v '^#' "$ENV_FILE" | grep -v '^$' | wc -l)
echo -e "Secrets à migrer : ${GREEN}$TOTAL${NC}"
echo ""

# Demander confirmation
read -p "Continuer la migration ? (o/N) : " CONFIRM
if [[ ! "$CONFIRM" =~ ^[oO]$ ]]; then
    echo "Migration annulée."
    exit 0
fi

echo ""
echo "Migration en cours..."
echo ""

# Compteurs
SUCCESS=0
FAILED=0

# Lire chaque ligne du .env
while IFS= read -r line; do
    # Ignorer les commentaires et lignes vides
    if [[ "$line" =~ ^#.*$ ]] || [ -z "$line" ]; then
        continue
    fi
    
    # Extraire la clé et la valeur
    if [[ "$line" =~ ^([^=]+)=(.*)$ ]]; then
        key="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        
        # Retirer les guillemets si présents
        value=$(echo "$value" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
        
        # Migrer le secret
        echo -n "  Migration de $key... "
        if vault $VAULT_ARG set "$key" --value "$value" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}"
            ((SUCCESS++))
        else
            echo -e "${RED}✗${NC}"
            ((FAILED++))
        fi
    fi
done < "$ENV_FILE"

echo ""
echo -e "${GREEN}=== Migration terminée ===${NC}"
echo ""
echo "Résumé :"
echo -e "  Réussis : ${GREEN}$SUCCESS${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "  Échoués : ${RED}$FAILED${NC}"
fi
echo ""

# Vérifier les secrets migrés
echo "Secrets dans le vault :"
vault $VAULT_ARG list
echo ""

# Instructions post-migration
echo -e "${YELLOW}⚠️  IMPORTANT - Prochaines étapes :${NC}"
echo ""
echo "1. Vérifiez que tous les secrets ont été migrés correctement"
echo "   vault list"
echo ""
echo "2. Testez votre application avec les secrets injectés"
echo "   vault exec -- votre-commande"
echo ""
echo "3. Si tout fonctionne, sauvegardez le fichier .env dans un endroit sûr"
echo "   cp $ENV_FILE ${ENV_FILE}.backup"
echo ""
echo "4. Supprimez le fichier .env"
echo "   rm $ENV_FILE"
echo ""
echo "5. Vérifiez que .env est dans votre .gitignore"
echo "   grep -q '^\.env$' .gitignore || echo '.env' >> .gitignore"
echo ""
echo -e "${GREEN}Migration réussie ! Vos secrets sont maintenant chiffrés dans le vault.${NC}"
