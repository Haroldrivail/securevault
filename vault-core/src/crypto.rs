use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params,
};
use rand::RngCore;

use crate::error::{VaultError, VaultResult};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use base64::Engine;

/// Taille du sel en bytes — 32 bytes = 256 bits, standard recommandé
pub const SALT_SIZE: usize = 32;

/// Taille de la clé AES-256 en bytes
pub const KEY_SIZE: usize = 32;

/// Taille du nonce AES-GCM en bytes — 96 bits, requis par le standard
pub const NONCE_SIZE: usize = 12;

/// Génère un sel aléatoire cryptographiquement sûr.
///
/// `OsRng` utilise le générateur aléatoire du système d'exploitation
/// (`/dev/urandom` sur Linux, `CryptGenRandom` sur Windows).
/// C'est toujours préférable à un générateur pseudo-aléatoire.
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// Génère un nonce aléatoire unique pour chaque opération de chiffrement.
///
/// CRITIQUE : Ne jamais réutiliser un nonce avec la même clé en AES-GCM.
/// La réutilisation permet à un attaquant de récupérer la clé secrète.
pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Dérive une clé cryptographique de 256 bits à partir d'un mot de passe
/// et d'un sel, en utilisant Argon2id.
///
/// # Pourquoi Argon2id plutôt que PBKDF2 ?
///
/// PBKDF2 est résistant aux attaques par force brute CPU, mais pas aux
/// attaques GPU/ASIC modernes car il a une faible utilisation mémoire.
/// Argon2id est "memory-hard" : il force l'attaquant à utiliser beaucoup
/// de RAM, ce qui rend les attaques GPU prohibitivement coûteuses.
///
/// Les paramètres choisis :
/// - `m_cost = 64 * 1024` : 64 MB de RAM (bon équilibre sécurité/performance)
/// - `t_cost = 3` : 3 itérations
/// - `p_cost = 1` : 1 thread (simplicité)
///
/// Sur un PC moderne, cette dérivation prend ~200ms — acceptable pour un
/// humain mais catastrophique pour un attaquant (5 essais/seconde max).
pub fn derive_key(password: &str, salt: &[u8]) -> VaultResult<[u8; KEY_SIZE]> {
    // Convertir le sel en SaltString (format attendu par argon2)
    // On encode le sel en base64 car SaltString attend de l'ASCII
    let salt_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(salt);
    let salt_string = SaltString::from_b64(&salt_b64)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;

    // Configurer Argon2id avec des paramètres appropriés
    let params = Params::new(
        64 * 1024, // mémoire : 64 MB
        3,         // itérations
        1,         // parallélisme
        Some(KEY_SIZE), // taille de sortie
    )
    .map_err(|e| VaultError::CryptoError(e.to_string()))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id, // Argon2id = hybride, recommandé
        argon2::Version::V0x13,
        params,
    );

    // Hasher le mot de passe
    let hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;

    // Extraire les bytes de la clé depuis le hash
    let hash_bytes = hash
        .hash
        .ok_or_else(|| VaultError::CryptoError("Hash vide".to_string()))?;

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(hash_bytes.as_bytes());
    Ok(key)
}

/// Chiffre une valeur en clair et retourne le ciphertext.
///
/// # AES-256-GCM : Chiffrement Authentifié (AEAD)
///
/// GCM (Galois/Counter Mode) est un mode d'opération qui fournit :
/// 1. **Confidentialité** : les données sont chiffrées
/// 2. **Intégrité** : un tag d'authentification détecte toute modification
/// 3. **Authenticité** : seul celui qui possède la clé peut créer un tag valide
///
/// C'est crucial : si quelqu'un modifie le fichier vault sur disque, le
/// déchiffrement échouera avec une erreur d'authentification, pas silencieusement.
///
/// # Arguments
/// - `key` : clé de 32 bytes dérivée par Argon2
/// - `nonce` : nonce de 12 bytes UNIQUE pour ce message (jamais réutilisé)
/// - `plaintext` : données en clair à chiffrer
pub fn encrypt(key: &[u8; KEY_SIZE], nonce: &[u8], plaintext: &[u8]) -> VaultResult<Vec<u8>> {
    // Créer le chiffreur AES-256-GCM avec la clé fournie
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;

    // Convertir le slice de nonce en type Nonce<12 bytes>
    let nonce = Nonce::from_slice(nonce);

    // Chiffrer — le ciphertext inclut le tag GCM de 16 bytes à la fin
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::CryptoError(format!("Chiffrement échoué : {}", e)))
}

/// Déchiffre un ciphertext et retourne les données en clair.
///
/// Si la clé est incorrecte OU si le ciphertext a été altéré,
/// le tag GCM ne correspondra pas et la fonction retourne une erreur.
/// C'est une propriété fondamentale de l'AEAD : on ne peut pas déchiffrer
/// silencieusement des données corrompues ou des mots de passe incorrects.
pub fn decrypt(key: &[u8; KEY_SIZE], nonce: &[u8], ciphertext: &[u8]) -> VaultResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    cipher.decrypt(nonce, ciphertext).map_err(|_| {
        // On ne révèle PAS le détail de l'erreur GCM pour éviter les oracles
        // (les attaques par oracle de déchiffrement exploitent les messages d'erreur précis)
        VaultError::InvalidMasterPassword
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test du cycle complet : dérivation de clé + chiffrement + déchiffrement
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "mot_de_passe_super_secret";
        let salt = generate_salt();

        // Dériver la clé
        let key = derive_key(password, &salt).expect("Dérivation de clé échouée");

        let plaintext = b"DATABASE_PASSWORD=postgres123";
        let nonce = generate_nonce();

        // Chiffrer
        let ciphertext = encrypt(&key, &nonce, plaintext).expect("Chiffrement échoué");

        // Le ciphertext ne doit pas être identique au plaintext
        assert_ne!(ciphertext, plaintext);

        // Déchiffrer
        let decrypted = decrypt(&key, &nonce, &ciphertext).expect("Déchiffrement échoué");
        assert_eq!(decrypted, plaintext);
    }

    /// Un mauvais mot de passe doit retourner une erreur, pas des données corrompues
    #[test]
    fn test_wrong_password_fails() {
        let salt = generate_salt();
        let key_correct = derive_key("bon_mdp", &salt).unwrap();
        let key_wrong = derive_key("mauvais_mdp", &salt).unwrap();

        let nonce = generate_nonce();
        let ciphertext = encrypt(&key_correct, &nonce, b"secret").unwrap();

        // Le déchiffrement avec la mauvaise clé doit échouer
        let result = decrypt(&key_wrong, &nonce, &ciphertext);
        assert!(result.is_err());
        assert!(matches!(result, Err(VaultError::InvalidMasterPassword)));
    }

    /// Les nonces doivent être uniques — deux appels ne doivent jamais retourner le même nonce
    #[test]
    fn test_nonce_uniqueness() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        // La probabilité de collision est 1/2^96 — si ce test échoue, votre OS est cassé
        assert_ne!(nonce1, nonce2);
    }

    /// Modifier le ciphertext doit causer un échec d'authentification
    #[test]
    fn test_tampered_ciphertext_detected() {
        let salt = generate_salt();
        let key = derive_key("mdp", &salt).unwrap();
        let nonce = generate_nonce();
        let mut ciphertext = encrypt(&key, &nonce, b"valeur_secrete").unwrap();

        // Modifier un byte du ciphertext
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }
}
