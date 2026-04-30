use thiserror::Error;

/// Toutes les erreurs possibles du vault.
///
/// `thiserror::Error` dérive automatiquement `std::error::Error`, `Display`, et `Debug`.
/// Chaque variante peut avoir un message personnalisé via `#[error("...")]`.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Mot de passe maître incorrect (déchiffrement échoue)
    #[error("Mot de passe maître invalide")]
    InvalidMasterPassword,

    /// Le fichier vault est corrompu ou dans un format inconnu
    #[error("Vault corrompu ou format invalide : {reason}")]
    CorruptedVault { reason: String },

    /// La clé demandée n'existe pas dans le vault
    #[error("Secret introuvable : {key}")]
    SecretNotFound { key: String },

    /// Le secret a expiré
    #[error("Le secret '{key}' a expiré le {expired_at}")]
    SecretExpired {
        key: String,
        expired_at: String,
    },

    /// Erreur lors du chiffrement ou déchiffrement
    #[error("Erreur cryptographique : {0}")]
    CryptoError(String),

    /// Erreur d'entrée/sortie (lecture/écriture fichier)
    #[error("Erreur I/O : {0}")]
    IoError(#[from] std::io::Error),

    /// Erreur de sérialisation/désérialisation
    #[error("Erreur de sérialisation : {0}")]
    SerializationError(String),

    /// Le vault n'a pas encore été initialisé
    #[error("Vault non initialisé. Lancez `vault init` d'abord.")]
    VaultNotInitialized,
}

/// Alias de résultat pour ne pas répéter `VaultError` partout
pub type VaultResult<T> = Result<T, VaultError>;