use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::error::{VaultError, VaultResult};

/// Type d'opération effectuée sur le vault
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperation {
    /// Initialisation du vault
    Init,
    /// Ajout ou mise à jour d'un secret
    Set { key: String },
    /// Lecture d'un secret
    Get { key: String },
    /// Suppression d'un secret
    Delete { key: String },
    /// Listage des secrets
    List { tag_filter: Option<String> },
    /// Rotation du mot de passe maître
    RotateKey,
}

/// Entrée dans le journal d'audit
///
/// Chaque opération est enregistrée avec :
/// - Qui : l'utilisateur système (process owner)
/// - Quoi : le type d'opération
/// - Quand : timestamp UTC
/// - Depuis quel processus : PID
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditEntry {
    /// Timestamp de l'opération
    pub timestamp: DateTime<Utc>,
    
    /// Type d'opération effectuée
    pub operation: AuditOperation,
    
    /// Utilisateur système qui a effectué l'opération
    pub user: String,
    
    /// ID du processus qui a effectué l'opération
    pub process_id: u32,
    
    /// Succès ou échec de l'opération
    pub success: bool,
    
    /// Message d'erreur optionnel en cas d'échec
    pub error_message: Option<String>,
}

impl AuditEntry {
    /// Crée une nouvelle entrée d'audit pour une opération réussie
    pub fn success(operation: AuditOperation) -> Self {
        Self {
            timestamp: Utc::now(),
            operation,
            user: get_current_user(),
            process_id: std::process::id(),
            success: true,
            error_message: None,
        }
    }
    
    /// Crée une nouvelle entrée d'audit pour une opération échouée
    pub fn failure(operation: AuditOperation, error: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            operation,
            user: get_current_user(),
            process_id: std::process::id(),
            success: false,
            error_message: Some(error.to_string()),
        }
    }
}

/// Récupère le nom de l'utilisateur système courant
fn get_current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Journal d'audit immuable (append-only)
///
/// Le journal est stocké dans un fichier texte où chaque ligne est une entrée JSON.
/// Format : JSON Lines (JSONL) — une entrée par ligne.
///
/// # Propriétés de sécurité :
/// - Append-only : on n'écrit jamais au milieu du fichier
/// - Pas de suppression : les entrées ne sont jamais effacées
/// - Horodatage : chaque opération est datée
/// - Traçabilité : qui, quoi, quand, depuis quel processus
pub struct AuditLog {
    path: std::path::PathBuf,
}

impl AuditLog {
    /// Crée ou ouvre un journal d'audit
    ///
    /// Le fichier est créé s'il n'existe pas.
    /// Le répertoire parent est créé automatiquement si nécessaire.
    pub fn new(path: impl AsRef<Path>) -> VaultResult<Self> {
        let path = path.as_ref().to_path_buf();
        
        // Créer le répertoire parent si nécessaire
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        // Créer le fichier s'il n'existe pas
        if !path.exists() {
            File::create(&path)?;
        }
        
        Ok(Self { path })
    }
    
    /// Enregistre une opération réussie dans le journal
    pub fn log_success(&self, operation: AuditOperation) -> VaultResult<()> {
        let entry = AuditEntry::success(operation);
        self.append_entry(&entry)
    }
    
    /// Enregistre une opération échouée dans le journal
    pub fn log_failure(&self, operation: AuditOperation, error: &str) -> VaultResult<()> {
        let entry = AuditEntry::failure(operation, error);
        self.append_entry(&entry)
    }
    
    /// Ajoute une entrée au journal (append-only)
    fn append_entry(&self, entry: &AuditEntry) -> VaultResult<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        
        // Sérialiser en JSON compact (une ligne)
        let json = serde_json::to_string(entry)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;
        
        // Écrire avec newline
        writeln!(file, "{}", json)?;
        
        // Forcer l'écriture sur disque pour garantir la durabilité
        file.sync_all()?;
        
        Ok(())
    }
    
    /// Lit toutes les entrées du journal
    ///
    /// Retourne un vecteur de toutes les entrées, dans l'ordre chronologique.
    /// Les lignes invalides sont ignorées (avec un warning).
    pub fn read_all(&self) -> VaultResult<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        
        let mut entries = Vec::new();
        
        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            
            // Ignorer les lignes vides
            if line.trim().is_empty() {
                continue;
            }
            
            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    eprintln!(
                        "Warning: Ligne {} du journal d'audit invalide : {}",
                        line_num + 1,
                        e
                    );
                }
            }
        }
        
        Ok(entries)
    }
    
    /// Lit les N dernières entrées du journal
    pub fn read_last(&self, n: usize) -> VaultResult<Vec<AuditEntry>> {
        let all = self.read_all()?;
        let start = all.len().saturating_sub(n);
        Ok(all[start..].to_vec())
    }
    
    /// Filtre les entrées par type d'opération
    pub fn filter_by_operation(&self, op_type: &str) -> VaultResult<Vec<AuditEntry>> {
        let all = self.read_all()?;
        
        Ok(all
            .into_iter()
            .filter(|entry| {
                let op_name = match &entry.operation {
                    AuditOperation::Init => "init",
                    AuditOperation::Set { .. } => "set",
                    AuditOperation::Get { .. } => "get",
                    AuditOperation::Delete { .. } => "delete",
                    AuditOperation::List { .. } => "list",
                    AuditOperation::RotateKey => "rotate",
                };
                op_name == op_type
            })
            .collect())
    }
    
    /// Filtre les entrées par clé de secret
    pub fn filter_by_key(&self, key: &str) -> VaultResult<Vec<AuditEntry>> {
        let all = self.read_all()?;
        
        Ok(all
            .into_iter()
            .filter(|entry| match &entry.operation {
                AuditOperation::Set { key: k }
                | AuditOperation::Get { key: k }
                | AuditOperation::Delete { key: k } => k == key,
                _ => false,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_audit_log_append_and_read() {
        let temp_file = NamedTempFile::new().unwrap();
        let log = AuditLog::new(temp_file.path()).unwrap();
        
        // Enregistrer quelques opérations
        log.log_success(AuditOperation::Init).unwrap();
        log.log_success(AuditOperation::Set {
            key: "test_key".to_string(),
        })
        .unwrap();
        log.log_failure(
            AuditOperation::Get {
                key: "missing".to_string(),
            },
            "Secret not found",
        )
        .unwrap();
        
        // Lire toutes les entrées
        let entries = log.read_all().unwrap();
        assert_eq!(entries.len(), 3);
        
        // Vérifier les types d'opérations
        assert!(matches!(entries[0].operation, AuditOperation::Init));
        assert!(matches!(entries[1].operation, AuditOperation::Set { .. }));
        assert!(matches!(entries[2].operation, AuditOperation::Get { .. }));
        
        // Vérifier les statuts
        assert!(entries[0].success);
        assert!(entries[1].success);
        assert!(!entries[2].success);
    }
    
    #[test]
    fn test_audit_log_filter_by_key() {
        let temp_file = NamedTempFile::new().unwrap();
        let log = AuditLog::new(temp_file.path()).unwrap();
        
        log.log_success(AuditOperation::Set {
            key: "key1".to_string(),
        })
        .unwrap();
        log.log_success(AuditOperation::Set {
            key: "key2".to_string(),
        })
        .unwrap();
        log.log_success(AuditOperation::Get {
            key: "key1".to_string(),
        })
        .unwrap();
        
        let filtered = log.filter_by_key("key1").unwrap();
        assert_eq!(filtered.len(), 2);
    }
}
