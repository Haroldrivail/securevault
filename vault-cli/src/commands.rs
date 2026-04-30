use anyhow::{Context, Result};
use chrono::{NaiveDate, TimeZone, Utc};
use colored::Colorize;
use std::path::Path;
use vault_core::{crypto, storage, types::VaultEntry, VaultError};

use crate::password::{prompt_password, prompt_password_confirm};

pub fn cmd_init(vault_path: &Path) -> Result<()> {
    println!("{}", "Initialisation du vault SecureVault...".bold());

    let password = prompt_password_confirm()?;

    storage::init_vault(&password, vault_path)
        .context("Échec de l'initialisation du vault")?;

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

pub fn cmd_set(
    vault_path: &Path,
    key: &str,
    value_opt: Option<String>,
    tags: Vec<String>,
    expires_str: Option<String>,
) -> Result<()> {
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
    let mut vault = storage::load_vault(&password, vault_path)
        .map_err(map_vault_error)?;

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
    storage::save_vault(&vault, &password, vault_path)?;

    println!("{} Secret '{}' enregistré.", "✓".green().bold(), key);
    Ok(())
}

pub fn cmd_get(vault_path: &Path, key: &str) -> Result<()> {
    let password = prompt_password("Mot de passe maître : ")?;
    let vault = storage::load_vault(&password, vault_path).map_err(map_vault_error)?;

    let entry = vault.entries.get(key).ok_or_else(|| {
        anyhow::anyhow!("Secret '{}' introuvable dans le vault", key)
    })?;

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
    let plaintext = crypto::decrypt(&key_bytes, &entry.nonce, &entry.encrypted_value)?;
    let value = String::from_utf8(plaintext).context("Valeur non valide UTF-8")?;

    // Afficher uniquement la valeur (pour permettre `vault get KEY | xclip`)
    println!("{}", value);

    Ok(())
}

pub fn cmd_delete(vault_path: &Path, key: &str) -> Result<()> {
    let password = prompt_password("Mot de passe maître : ")?;
    let mut vault = storage::load_vault(&password, vault_path).map_err(map_vault_error)?;

    if vault.entries.remove(key).is_none() {
        anyhow::bail!("Secret '{}' introuvable", key);
    }

    storage::save_vault(&vault, &password, vault_path)?;
    println!("{} Secret '{}' supprimé.", "✓".green().bold(), key);

    Ok(())
}

pub fn cmd_list(vault_path: &Path, tag_filter: Option<String>) -> Result<()> {
    let password = prompt_password("Mot de passe maître : ")?;
    let vault = storage::load_vault(&password, vault_path).map_err(map_vault_error)?;

    let mut entries: Vec<&VaultEntry> = vault.entries.values().collect();

    // Filtrer par tag si demandé
    if let Some(ref tag) = tag_filter {
        entries.retain(|e| e.tags.contains(tag));
    }

    // Trier alphabétiquement
    entries.sort_by_key(|e| &e.key);

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
    println!("{}", "Rotation du mot de passe maître".bold());

    let old_password = prompt_password("Ancien mot de passe : ")?;
    println!("Nouveau mot de passe :");
    let new_password = prompt_password_confirm()?;

    storage::rotate_key(&old_password, &new_password, vault_path)
        .context("Échec de la rotation")?;

    println!("{} Mot de passe changé avec succès.", "✓".green().bold());
    Ok(())
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