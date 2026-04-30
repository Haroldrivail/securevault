use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Un secret est une paire clé/valeur chiffrée, enrichie de métadonnées.
///
/// On dérive `Serialize` et `Deserialize` pour pouvoir sérialiser avec bincode.
/// `Clone` est nécessaire car on manipulera des copies pour la rotation de clé.
/// `Debug` est intentionnellement absent sur les champs sensibles.
#[derive(Serialize, Deserialize, Clone)]
pub struct VaultEntry {
    /// Le nom du secret, ex: "DATABASE_PASSWORD"
    pub key: String,

    /// La valeur chiffrée (bytes bruts après AES-GCM)
    pub encrypted_value: Vec<u8>,

    /// Le nonce AES-GCM utilisé pour ce chiffrement (12 bytes)
    /// Chaque chiffrement DOIT utiliser un nonce différent — voir section 3.3
    pub nonce: Vec<u8>,

    /// Date de création de l'entrée
    pub created_at: DateTime<Utc>,

    /// Date d'expiration optionnelle — None = jamais expire
    pub expires_at: Option<DateTime<Utc>>,

    /// Tags libres pour organiser les secrets, ex: ["production", "database"]
    pub tags: Vec<String>,
}

/// Le vault est le conteneur principal de tous les secrets.
#[derive(Serialize, Deserialize, Clone)]
pub struct Vault {
    /// Version du format de données — permet les migrations futures
    pub version: u32,

    /// Les secrets, indexés par leur nom
    pub entries: HashMap<String, VaultEntry>,

    /// Sel utilisé pour la dérivation de clé (PBKDF2/Argon2)
    /// Stocké en clair — le sel n'est pas secret, il sert à personnaliser le hash
    pub salt: Vec<u8>,
}

impl Vault {
    /// Crée un nouveau vault vide avec un sel aléatoire.
    /// L'appelant doit fournir le sel (généré dans le moteur crypto).
    pub fn new(salt: Vec<u8>) -> Self {
        Vault {
            version: 1,
            entries: HashMap::new(),
            salt,
        }
    }
}

/// Représente un secret en clair, uniquement en mémoire.
/// Cette structure ne doit JAMAIS être sérialisée sur disque.
#[derive(Clone)]
pub struct Secret {
    pub key: String,
    pub value: String, // valeur en clair — en RAM seulement
}
