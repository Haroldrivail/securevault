use anyhow::{Context, Result};
use chrono::{NaiveDate, TimeZone, Utc};
use colored::Colorize;
use std::path::Path;
use vault_core::{audit::AuditOperation, crypto, storage, types::VaultEntry, AuditLog, VaultError};

use crate::password::{prompt_password, prompt_password_confirm};

/// Obtient le chemin du fichier d'audit log à partir du chemin du vault
fn get_audit_log_path(vault_path: &Path) -> std::path::PathBuf {
    vault_path.with_extension("audit.log")
}

pub fn cmd_init(vault_path: &Path) -> Result<()> {
    println!("{}", "Initialisation du vault SecureVault...".bold());

    let password = prompt_password_confirm()?;

    let audit_log = AuditLog::new(get_audit_log_path(vault_path))?;

    match storage::init_vault(&password, vault_path) {
        Ok(_) => {
            audit_log.log_success(AuditOperation::Init)?;
            println!(
                "{} Vault créé dans : {}",
                "✓".green().bold(),
                vault_path.display()
            );
            println!(
                "{}",
                "IMPORTANT : Conservez votre mot de passe maître en lieu sûr.\n\
                 Il est impossible de récupérer les secrets sans lui."
                    .yellow()
            );
            Ok(())
        }
        Err(e) => {
            audit_log.log_failure(AuditOperation::Init, &e.to_string())?;
            Err(e.into())
        }
    }
}

pub fn cmd_set(
    vault_path: &Path,
    key: &str,
    value_opt: Option<String>,
    tags: Vec<String>,
    expires_str: Option<String>,
) -> Result<()> {
    let audit_log = AuditLog::new(get_audit_log_path(vault_path))?;
    let operation = AuditOperation::Set {
        key: key.to_string(),
    };

    // Récupérer ou demander la valeur
    let value = match value_opt {
        Some(v) => v,
        None => {
            // Saisie sécurisée sans écho — idéal pour les mots de passe
            rpassword::prompt_password(&format!("Valeur pour '{}' : ", key))
                .context("Impossible de lire la valeur")?
        }
    };

    let password = prompt_password("Mot de passe maître : ")?;

    // Charger le vault existant
    let mut vault = match storage::load_vault(&password, vault_path) {
        Ok(v) => v,
        Err(e) => {
            audit_log.log_failure(operation, &e.to_string())?;
            return Err(map_vault_error(e));
        }
    };

    // Dériver la clé pour chiffrer la nouvelle valeur
    let key_bytes = crypto::derive_key(&password, &vault.salt)?;
    let nonce = crypto::generate_nonce();
    let encrypted_value = crypto::encrypt(&key_bytes, &nonce, value.as_bytes())?;

    // Parser la date d'expiration si fournie
    let expires_at = expires_str
        .map(|s| {
            NaiveDate::parse_from_str(&s, "%Y-%m-%d")
                .map(|d| Utc.from_utc_datetime(&d.and_hms_opt(23, 59, 59).unwrap()))
                .context(format!("Format de date invalide '{}' — attendu : YYYY-MM-DD", s))
        })
        .transpose()?;

    // Créer l'entrée
    let entry = VaultEntry {
        key: key.to_string(),
        encrypted_value,
        nonce,
        created_at: Utc::now(),
        expires_at,
        tags,
    };

    vault.entries.insert(key.to_string(), entry);
    
    match storage::save_vault(&vault, &password, vault_path) {
        Ok(_) => {
            audit_log.log_success(operation)?;
            println!("{} Secret '{}' enregistré.", "✓".green().bold(), key);
            Ok(())
        }
        Err(e) => {
            audit_log.log_failure(operation, &e.to_string())?;
            Err(e.into())
        }
    }
}

pub fn cmd_get(vault_path: &Path, key: &str) -> Result<()> {
    let audit_log = AuditLog::new(get_audit_log_path(vault_path))?;
    let operation = AuditOperation::Get {
        key: key.to_string(),
    };

    let password = prompt_password("Mot de passe maître : ")?;
    let vault = match storage::load_vault(&password, vault_path) {
        Ok(v) => v,
        Err(e) => {
            audit_log.log_failure(operation, &e.to_string())?;
            return Err(map_vault_error(e));
        }
    };

    let entry = match vault.entries.get(key) {
        Some(e) => e,
        None => {
            let err_msg = format!("Secret '{}' introuvable dans le vault", key);
            audit_log.log_failure(operation, &err_msg)?;
            return Err(anyhow::anyhow!(err_msg));
        }
    };

    // Vérifier l'expiration
    if let Some(expires) = entry.expires_at {
        if Utc::now() > expires {
            eprintln!(
                "{} Le secret '{}' a expiré le {}",
                "⚠".yellow(),
                key,
                expires.format("%Y-%m-%d")
            );
            // On continue quand même — l'utilisateur est averti
        }
    }

    // Déchiffrer
    let key_bytes = crypto::derive_key(&password, &vault.salt)?;
    let plaintext = match crypto::decrypt(&key_bytes, &entry.nonce, &entry.encrypted_value) {
        Ok(p) => p,
        Err(e) => {
            audit_log.log_failure(operation, &e.to_string())?;
            return Err(e.into());
        }
    };
    
    let value = String::from_utf8(plaintext).context("Valeur non valide UTF-8")?;

    audit_log.log_success(operation)?;

    // Afficher uniquement la valeur (pour permettre `vault get KEY | xclip`)
    println!("{}", value);

    Ok(())
}

pub fn cmd_delete(vault_path: &Path, key: &str) -> Result<()> {
    let audit_log = AuditLog::new(get_audit_log_path(vault_path))?;
    let operation = AuditOperation::Delete {
        key: key.to_string(),
    };

    let password = prompt_password("Mot de passe maître : ")?;
    let mut vault = match storage::load_vault(&password, vault_path) {
        Ok(v) => v,
        Err(e) => {
            audit_log.log_failure(operation, &e.to_string())?;
            return Err(map_vault_error(e));
        }
    };

    if vault.entries.remove(key).is_none() {
        let err_msg = format!("Secret '{}' introuvable", key);
        audit_log.log_failure(operation, &err_msg)?;
        anyhow::bail!(err_msg);
    }

    match storage::save_vault(&vault, &password, vault_path) {
        Ok(_) => {
            audit_log.log_success(operation)?;
            println!("{} Secret '{}' supprimé.", "✓".green().bold(), key);
            Ok(())
        }
        Err(e) => {
            audit_log.log_failure(operation, &e.to_string())?;
            Err(e.into())
        }
    }
}

pub fn cmd_list(vault_path: &Path, tag_filter: Option<String>) -> Result<()> {
    let audit_log = AuditLog::new(get_audit_log_path(vault_path))?;
    let operation = AuditOperation::List {
        tag_filter: tag_filter.clone(),
    };

    let password = prompt_password("Mot de passe maître : ")?;
    let vault = match storage::load_vault(&password, vault_path) {
        Ok(v) => v,
        Err(e) => {
            audit_log.log_failure(operation, &e.to_string())?;
            return Err(map_vault_error(e));
        }
    };

    let mut entries: Vec<&VaultEntry> = vault.entries.values().collect();

    // Filtrer par tag si demandé
    if let Some(ref tag) = tag_filter {
        entries.retain(|e| e.tags.contains(tag));
    }

    // Trier alphabétiquement
    entries.sort_by_key(|e| &e.key);

    audit_log.log_success(operation)?;

    if entries.is_empty() {
        println!("{}", "Aucun secret dans le vault.".dimmed());
        return Ok(());
    }

    println!("{}", "Secrets disponibles :".bold());
    println!("{:-<50}", "");

    let now = Utc::now();
    for entry in &entries {
        // Indicateur d'expiration
        let expiry_indicator = match entry.expires_at {
            None => "".to_string(),
            Some(exp) if now > exp => format!(" {}", "[EXPIRÉ]".red()),
            Some(exp) => format!(" [expire le {}]", exp.format("%Y-%m-%d")).yellow().to_string(),
        };

        // Tags
        let tags_str = if entry.tags.is_empty() {
            String::new()
        } else {
            format!(" ({})", entry.tags.join(", ")).cyan().to_string()
        };

        println!(
            "  {} {}{}{}",
            "•".green(),
            entry.key.bold(),
            tags_str,
            expiry_indicator
        );
    }

    println!("{:-<50}", "");
    println!("Total : {} secret(s)", entries.len());

    Ok(())
}

pub fn cmd_rotate(vault_path: &Path) -> Result<()> {
    let audit_log = AuditLog::new(get_audit_log_path(vault_path))?;
    let operation = AuditOperation::RotateKey;

    println!("{}", "Rotation du mot de passe maître".bold());

    let old_password = prompt_password("Ancien mot de passe : ")?;
    println!("Nouveau mot de passe :");
    let new_password = prompt_password_confirm()?;

    match storage::rotate_key(&old_password, &new_password, vault_path) {
        Ok(_) => {
            audit_log.log_success(operation)?;
            println!("{} Mot de passe changé avec succès.", "✓".green().bold());
            Ok(())
        }
        Err(e) => {
            audit_log.log_failure(operation, &e.to_string())?;
            Err(anyhow::anyhow!("Échec de la rotation : {}", e))
        }
    }
}

/// Convertit les erreurs vault en messages utilisateur clairs
fn map_vault_error(e: VaultError) -> anyhow::Error {
    match e {
        VaultError::InvalidMasterPassword => {
            anyhow::anyhow!("{} Mot de passe incorrect.", "✗".red())
        }
        VaultError::VaultNotInitialized => {
            anyhow::anyhow!("Vault non initialisé. Lancez `vault init` d'abord.")
        }
        other => anyhow::anyhow!("{}", other),
    }
}

/// Affiche le journal d'audit
pub fn cmd_audit(
    vault_path: &Path,
    last: Option<usize>,
    operation_filter: Option<String>,
    key_filter: Option<String>,
) -> Result<()> {
    let audit_log = AuditLog::new(get_audit_log_path(vault_path))?;

    // Récupérer les entrées selon les filtres
    let entries = if let Some(key) = key_filter {
        audit_log.filter_by_key(&key)?
    } else if let Some(op) = operation_filter {
        audit_log.filter_by_operation(&op)?
    } else if let Some(n) = last {
        audit_log.read_last(n)?
    } else {
        audit_log.read_all()?
    };

    if entries.is_empty() {
        println!("{}", "Aucune entrée dans le journal d'audit.".dimmed());
        return Ok(());
    }

    println!("{}", "Journal d'audit :".bold());
    println!("{:-<100}", "");

    for entry in &entries {
        // Formater le timestamp
        let timestamp = entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC");

        // Formater l'opération
        let operation_str = match &entry.operation {
            AuditOperation::Init => "INIT".to_string(),
            AuditOperation::Set { key } => format!("SET {}", key),
            AuditOperation::Get { key } => format!("GET {}", key),
            AuditOperation::Delete { key } => format!("DELETE {}", key),
            AuditOperation::List { tag_filter } => {
                if let Some(tag) = tag_filter {
                    format!("LIST (tag: {})", tag)
                } else {
                    "LIST".to_string()
                }
            }
            AuditOperation::RotateKey => "ROTATE_KEY".to_string(),
        };

        // Indicateur de succès/échec
        let status = if entry.success {
            "✓".green().bold()
        } else {
            "✗".red().bold()
        };

        // Afficher l'entrée
        println!(
            "{} {} | {} | {} | PID: {}",
            status,
            timestamp.to_string().dimmed(),
            entry.user.cyan(),
            operation_str.bold(),
            entry.process_id
        );

        // Afficher le message d'erreur si présent
        if let Some(ref error) = entry.error_message {
            println!("    {} {}", "Erreur:".red(), error);
        }
    }

    println!("{:-<100}", "");
    println!("Total : {} entrée(s)", entries.len());

    Ok(())
}
