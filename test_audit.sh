#!/bin/bash

# Script de test pour la Partie 4 - Audit Log et Métadonnées
# Ce script démontre toutes les fonctionnalités du vault avec l'audit log

set -e

VAULT_PATH="./test_vault.db"
AUDIT_PATH="./test_vault.audit.log"

# Couleurs pour l'affichage
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Test de la Partie 4 : Audit Log et Métadonnées ===${NC}\n"

# Nettoyer les fichiers de test précédents
echo -e "${YELLOW}Nettoyage des fichiers de test précédents...${NC}"
rm -f "$VAULT_PATH" "$AUDIT_PATH" "${VAULT_PATH}.tmp"

# Test 1 : Initialisation du vault
echo -e "\n${GREEN}Test 1 : Initialisation du vault${NC}"
echo "test123" | cargo run --bin vault -- --vault "$VAULT_PATH" init

# Test 2 : Ajouter des secrets avec métadonnées
echo -e "\n${GREEN}Test 2 : Ajouter des secrets avec métadonnées${NC}"
echo -e "test123\nsecret_value_1" | cargo run --bin vault -- --vault "$VAULT_PATH" set API_KEY --tag production --tag api
echo -e "test123\ndb_password_123" | cargo run --bin vault -- --vault "$VAULT_PATH" set DB_PASSWORD --tag production --tag database --expires 2026-12-31
echo -e "test123\ndev_token_xyz" | cargo run --bin vault -- --vault "$VAULT_PATH" set DEV_TOKEN --tag development

# Test 3 : Lister les secrets
echo -e "\n${GREEN}Test 3 : Lister tous les secrets${NC}"
echo "test123" | cargo run --bin vault -- --vault "$VAULT_PATH" list

# Test 4 : Lister avec filtre par tag
echo -e "\n${GREEN}Test 4 : Lister les secrets avec tag 'production'${NC}"
echo "test123" | cargo run --bin vault -- --vault "$VAULT_PATH" list --tag production

# Test 5 : Récupérer un secret
echo -e "\n${GREEN}Test 5 : Récupérer un secret${NC}"
echo "test123" | cargo run --bin vault -- --vault "$VAULT_PATH" get API_KEY

# Test 6 : Supprimer un secret
echo -e "\n${GREEN}Test 6 : Supprimer un secret${NC}"
echo "test123" | cargo run --bin vault -- --vault "$VAULT_PATH" delete DEV_TOKEN

# Test 7 : Afficher tout l'audit log
echo -e "\n${GREEN}Test 7 : Afficher tout le journal d'audit${NC}"
cargo run --bin vault -- --vault "$VAULT_PATH" audit

# Test 8 : Afficher les 3 dernières entrées
echo -e "\n${GREEN}Test 8 : Afficher les 3 dernières entrées d'audit${NC}"
cargo run --bin vault -- --vault "$VAULT_PATH" audit --last 3

# Test 9 : Filtrer par opération
echo -e "\n${GREEN}Test 9 : Filtrer les opérations 'set'${NC}"
cargo run --bin vault -- --vault "$VAULT_PATH" audit --operation set

# Test 10 : Filtrer par clé
echo -e "\n${GREEN}Test 10 : Filtrer les opérations sur 'API_KEY'${NC}"
cargo run --bin vault -- --vault "$VAULT_PATH" audit --key API_KEY

# Test 11 : Rotation du mot de passe
echo -e "\n${GREEN}Test 11 : Rotation du mot de passe maître${NC}"
echo -e "test123\nnewpass456\nnewpass456" | cargo run --bin vault -- --vault "$VAULT_PATH" rotate

# Test 12 : Vérifier que le nouveau mot de passe fonctionne
echo -e "\n${GREEN}Test 12 : Vérifier l'accès avec le nouveau mot de passe${NC}"
echo "newpass456" | cargo run --bin vault -- --vault "$VAULT_PATH" list

# Test 13 : Afficher l'audit log final
echo -e "\n${GREEN}Test 13 : Journal d'audit final${NC}"
cargo run --bin vault -- --vault "$VAULT_PATH" audit

# Test 14 : Afficher le contenu brut du fichier d'audit
echo -e "\n${GREEN}Test 14 : Contenu brut du fichier d'audit (format JSONL)${NC}"
echo -e "${YELLOW}Premières lignes du fichier :${NC}"
head -n 5 "$AUDIT_PATH"

echo -e "\n${BLUE}=== Tests terminés avec succès ! ===${NC}"
echo -e "${YELLOW}Fichiers créés :${NC}"
echo "  - Vault : $VAULT_PATH"
echo "  - Audit Log : $AUDIT_PATH"
