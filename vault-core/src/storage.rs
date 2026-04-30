use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt, derive_key, encrypt, generate_nonce, generate_salt};
use crate::error::{VaultError, VaultResult};
use crate::types::Vault;

/// Identifiant magique du format de fichier — 8 bytes
const MAGIC: &[u8; 8] = b"SVAULT\x00\x01";

/// Version courante du format — incrémentez lors de changements incompatibles
const FORMAT_VERSION: u32 = 1;

/// Structure intermédiaire qui représente le fichier sur disque avant déchiffrement.
/// Elle est sérialisée en binaire et écrite dans le fichier.
#[derive(Serialize, Deserialize)]
struct VaultFile {
    magic: [u8; 8],
    version: u32,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    /// Les données du vault chiffrées avec AES-256-GCM
    encrypted_data: Vec<u8>,
}

/// Chiffre le vault et l'écrit sur disque.
///
/// # Flux de l'opération :
/// 1. Sérialiser `Vault` en bytes avec bincode
/// 2. Dériver la clé AES depuis le mot de passe et le sel du vault
/// 3. Générer un nouveau nonce aléatoire
/// 4. Chiffrer les bytes sérialisés
/// 5. Construire la structure `VaultFile` et la sérialiser sur disque
///
/// # Atomicité
/// On écrit dans un fichier temporaire, puis on renomme.
/// `rename` est atomique sur la plupart des systèmes de fichiers Unix :
/// si le processus crash pendant l'écriture, l'ancien vault est intact.
pub fn save_vault(vault: &Vault, password: &str, path: &Path) -> VaultResult<()> {
    // Étape 1 : Sérialiser le vault
    let plaintext = bincode::serialize(vault)
        .map_err(|e| VaultError::SerializationError(e.to_string()))?;

    // Étape 2 : Dériver la clé depuis le mot de passe et le sel du vault
    let key = derive_key(password, &vault.salt)?;

    // Étape 3 : Nouveau nonce pour chaque sauvegarde
    let nonce = generate_nonce();

    // Étape 4 : Chiffrer
    let encrypted_data = encrypt(&key, &nonce, &plaintext)?;

    // Étape 5 : Construire et écrire le fichier
    let vault_file = VaultFile {
        magic: *MAGIC,
        version: FORMAT_VERSION,
        salt: vault.salt.clone(),
        nonce,
        encrypted_data,
    };

    let serialized = bincode::serialize(&vault_file)
        .map_err(|e| VaultError::SerializationError(e.to_string()))?;

    // Écriture atomique via fichier temporaire
    let tmp_path = path.with_extension("vault.tmp");
    let mut file = File::create(&tmp_path)?;
    file.write_all(&serialized)?;
    file.flush()?; // S'assurer que les données sont sur disque avant le rename

    // Rename atomique
    fs::rename(&tmp_path, path)?;

    Ok(())
}

/// Lit et déchiffre un vault depuis le disque.
///
/// # Gestion des erreurs de corruption
/// Plusieurs niveaux de vérification :
/// 1. Le fichier existe et est lisible (IoError)
/// 2. La désérialisation bincode réussit (CorruptedVault)
/// 3. Le magic number correspond (CorruptedVault)
/// 4. La version est supportée (CorruptedVault)
/// 5. Le déchiffrement réussit — valide le mot de passe ET l'intégrité (InvalidMasterPassword)
/// 6. La désérialisation interne réussit (CorruptedVault)
pub fn load_vault(password: &str, path: &Path) -> VaultResult<Vault> {
    // Vérifier que le vault existe
    if !path.exists() {
        return Err(VaultError::VaultNotInitialized);
    }

    // Lire le fichier en entier
    let mut file = File::open(path)?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;

    // Désérialiser l'enveloppe
    let vault_file: VaultFile = bincode::deserialize(&raw)
        .map_err(|_| VaultError::CorruptedVault {
            reason: "Impossible de désérialiser l'en-tête".to_string(),
        })?;

    // Vérifier le magic number
    if &vault_file.magic != MAGIC {
        return Err(VaultError::CorruptedVault {
            reason: "Magic number invalide — ce n'est pas un fichier vault".to_string(),
        });
    }

    // Vérifier la version
    if vault_file.version != FORMAT_VERSION {
        return Err(VaultError::CorruptedVault {
            reason: format!(
                "Version {} non supportée (version actuelle : {})",
                vault_file.version, FORMAT_VERSION
            ),
        });
    }

    // Dériver la clé depuis le sel stocké dans le fichier
    let key = derive_key(password, &vault_file.salt)?;

    // Déchiffrer — si le mot de passe est incorrect, le tag GCM invalide => erreur
    let plaintext = decrypt(&key, &vault_file.nonce, &vault_file.encrypted_data)?;

    // Désérialiser le vault déchiffré
    let vault: Vault = bincode::deserialize(&plaintext)
        .map_err(|_| VaultError::CorruptedVault {
            reason: "Données internes corrompues après déchiffrement".to_string(),
        })?;

    Ok(vault)
}

/// Crée un nouveau vault vierge et le sauvegarde.
pub fn init_vault(password: &str, path: &Path) -> VaultResult<Vault> {
    if path.exists() {
        return Err(VaultError::CorruptedVault {
            reason: "Un vault existe déjà à cet emplacement".to_string(),
        });
    }

    // Créer le répertoire parent si nécessaire
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let salt = generate_salt();
    let vault = Vault::new(salt);
    save_vault(&vault, password, path)?;

    Ok(vault)
}

/// Change le mot de passe maître du vault.
///
/// # Algorithme :
/// 1. Charger et déchiffrer le vault avec l'ANCIEN mot de passe
/// 2. Générer un NOUVEAU sel (crucial — le sel doit changer avec le mot de passe)
/// 3. Reconstruire le vault avec le nouveau sel
/// 4. Re-chiffrer TOUTES les entrées avec la nouvelle clé
/// 5. Sauvegarder le nouveau vault
///
/// # Pourquoi générer un nouveau sel ?
/// Si on réutilise l'ancien sel, quelqu'un qui a capturé le fichier avant
/// la rotation peut tester des mots de passe avec l'ancien sel.
/// Un nouveau sel invalide toutes les tentatives précédentes.
pub fn rotate_key(old_password: &str, new_password: &str, path: &Path) -> VaultResult<()> {
    // Charger avec l'ancien mot de passe
    let old_vault = load_vault(old_password, path)?;

    // Nouveau sel + nouvelle clé
    let new_salt = generate_salt();
    let new_key = derive_key(new_password, &new_salt)?;

    // Re-chiffrer chaque entrée
    let mut new_entries = std::collections::HashMap::new();
    let old_key = derive_key(old_password, &old_vault.salt)?;

    for (key_name, mut entry) in old_vault.entries {
        // Déchiffrer avec l'ancienne clé
        let plaintext = decrypt(&old_key, &entry.nonce, &entry.encrypted_value)?;

        // Re-chiffrer avec la nouvelle clé et un nouveau nonce
        let new_nonce = generate_nonce();
        let new_ciphertext = encrypt(&new_key, &new_nonce, &plaintext)?;

        entry.encrypted_value = new_ciphertext;
        entry.nonce = new_nonce;
        new_entries.insert(key_name, entry);
    }

    let new_vault = Vault {
        version: old_vault.version,
        entries: new_entries,
        salt: new_salt,
    };

    save_vault(&new_vault, new_password, path)?;
    Ok(())
}