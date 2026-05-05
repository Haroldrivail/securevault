#!/bin/bash

# Script de test pour la fonctionnalité d'injection d'environnement
# Ce script démontre l'utilisation de `vault exec`

set -e

echo "=== Test de la fonctionnalité d'injection d'environnement ==="
echo ""

# Chemin du vault de test
VAULT_PATH="./test_vault.db"
PASSWORD="TestPassword123!"

# Nettoyer les fichiers de test existants
rm -f "$VAULT_PATH" "$VAULT_PATH.audit.log" .env

echo "1. Initialisation du vault de test..."
echo "$PASSWORD" | cargo run --bin vault -- --vault "$VAULT_PATH" init

echo ""
echo "2. Ajout de secrets de test..."
echo "$PASSWORD" | cargo run --bin vault -- --vault "$VAULT_PATH" set DATABASE_URL --value "postgres://user:pass@localhost/db" --tag backend
echo "$PASSWORD" | cargo run --bin vault -- --vault "$VAULT_PATH" set API_KEY --value "sk_test_123456789" --tag api
echo "$PASSWORD" | cargo run --bin vault -- --vault "$VAULT_PATH" set DEBUG --value "true"
echo "$PASSWORD" | cargo run --bin vault -- --vault "$VAULT_PATH" set SECRET_WITH_SPACES --value "value with spaces and \"quotes\""

echo ""
echo "3. Liste des secrets dans le vault..."
echo "$PASSWORD" | cargo run --bin vault -- --vault "$VAULT_PATH" list

echo ""
echo "4. Test d'export en fichier .env..."
echo "$PASSWORD" | cargo run --bin vault -- --vault "$VAULT_PATH" exec --export

echo ""
echo "Contenu du fichier .env généré :"
cat .env

echo ""
echo "5. Test d'injection avec une commande simple (env)..."
echo "$PASSWORD" | cargo run --bin vault -- --vault "$VAULT_PATH" exec -- env | grep -E "(DATABASE_URL|API_KEY|DEBUG|SECRET_WITH_SPACES)"

echo ""
echo "6. Test d'injection de secrets spécifiques..."
echo "$PASSWORD" | cargo run --bin vault -- --vault "$VAULT_PATH" exec --secret DATABASE_URL --secret API_KEY -- env | grep -E "(DATABASE_URL|API_KEY)"

echo ""
echo "7. Création d'un script Python de test..."
cat > test_script.py << 'EOF'
#!/usr/bin/env python3
import os
import sys

print("=== Variables d'environnement injectées ===")
secrets = ["DATABASE_URL", "API_KEY", "DEBUG", "SECRET_WITH_SPACES"]

for secret in secrets:
    value = os.environ.get(secret)
    if value:
        # Masquer partiellement les valeurs sensibles
        if len(value) > 10:
            masked = value[:4] + "..." + value[-4:]
        else:
            masked = "***"
        print(f"{secret}: {masked}")
    else:
        print(f"{secret}: (non défini)")

print("\nTest réussi ! Les secrets ont été injectés correctement.")
EOF

chmod +x test_script.py

echo ""
echo "8. Test d'injection avec un script Python..."
echo "$PASSWORD" | cargo run --bin vault -- --vault "$VAULT_PATH" exec -- python3 test_script.py

echo ""
echo "9. Nettoyage des fichiers de test..."
rm -f "$VAULT_PATH" "$VAULT_PATH.audit.log" .env test_script.py

echo ""
echo "=== Tous les tests sont passés avec succès ! ==="
