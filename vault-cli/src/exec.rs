use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use vault_core::{crypto, storage, VaultError};

use crate::password::prompt_password;

/// Lance une commande avec les secrets du vault injectés comme variables d'environnement.
///
/// # Sécurité
/// Les secrets sont injectés via `env()` — ils n'apparaissent pas dans :
/// - L'historique du shell (`.bash_history`)
/// - Les logs de commandes
/// - Les fichiers de configuration en clair
///
/// Attention : sous Linux, les variables d'environnement d'un processus
/// sont visibles dans `/proc/[pid]/environ` par l'utilisateur propriétaire.
/// C'est un compromis acceptable — les secrets ne sont pas sur disque en clair.
pub fn cmd_exec(
    vault_path: &Path,
    secret_keys: Vec<String>, // Secrets à injecter
    command: Vec<String>,      // La commande et ses arguments
    export_env: bool,          // Si true, exporte en .env au lieu d'exécuter
) -> Result<()> {
    if command.is_empty() && !export_env {
        anyhow::bail!("Aucune commande spécifiée. Utilisez : vault exec -- ma-commande");
    }

    let password = prompt_password("Mot de passe maître : ")?;

    // Charger le vault
    let vault = storage::load_vault(&password, vault_path)
        .context("Impossible de charger le vault")?;

    let key_bytes = crypto::derive_key(&password, &vault.salt)
        .context("Dérivation de clé échouée")?;

    // Déchiffrer les secrets demandés
    let mut env_vars: HashMap<String, String> = HashMap::new();

    // Si aucune clé spécifiée, injecter tous les secrets
    let keys_to_inject: Vec<&str> = if secret_keys.is_empty() {
        vault.entries.keys().map(|s| s.as_str()).collect()
    } else {
        secret_keys.iter().map(|s| s.as_str()).collect()
    };

    for key_name in &keys_to_inject {
        let entry = vault.entries.get(*key_name).ok_or_else(|| {
            anyhow::anyhow!("Secret '{}' introuvable dans le vault", key_name)
        })?;

        let plaintext = crypto::decrypt(&key_bytes, &entry.nonce, &entry.encrypted_value)
            .context(format!("Impossible de déchiffrer '{}'", key_name))?;

        let value = String::from_utf8(plaintext)
            .context(format!("'{}' contient des bytes non-UTF8", key_name))?;

        env_vars.insert(key_name.to_string(), value);
    }

    if export_env {
        // Mode export : écrire un fichier .env
        return export_to_dotenv(env_vars);
    }

    // Mode exec : lancer le processus enfant
    eprintln!(
        "{} Injection de {} secret(s) dans l'environnement",
        "→".cyan(),
        env_vars.len()
    );

    let program = &command[0];
    let args = &command[1..];

    // `Command` crée un processus enfant.
    // `.env_clear()` part d'un environnement vide pour ne pas leaker
    // des variables du shell parent non désirées. On peut l'omettre
    // si on veut hériter de l'environnement parent.
    let status = Command::new(program)
        .args(args)
        .envs(&env_vars) // Injecter nos secrets
        // Hériter stdin/stdout/stderr — le processus enfant utilise le terminal
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context(format!("Impossible de lancer '{}'", program))?;

    // Les secrets sont maintenant hors de portée — Rust les libère (drop)
    // Note : drop() ne garantit pas l'effacement mémoire, mais les secrets
    // ne sont plus accessibles depuis notre processus
    drop(env_vars);

    // Propager le code de sortie du processus enfant
    if !status.success() {
        let code = status.code().unwrap_or(1);
        std::process::exit(code);
    }

    Ok(())
}

/// Exporte les secrets dans un fichier .env (format KEY=VALUE)
fn export_to_dotenv(env_vars: HashMap<String, String>) -> Result<()> {
    let dotenv_path = std::path::Path::new(".env");

    // Avertissement si le fichier existe déjà
    if dotenv_path.exists() {
        eprintln!(
            "{} Fichier .env existant sera écrasé !",
            "⚠".yellow().bold()
        );
    }

    let mut content = String::from("# Généré par SecureVault — NE PAS COMMITER\n");
    let mut sorted_vars: Vec<_> = env_vars.into_iter().collect();
    sorted_vars.sort_by_key(|(k, _)| k.clone());

    for (key, value) in sorted_vars {
        // Échapper les valeurs contenant des caractères spéciaux
        let escaped_value = escape_dotenv_value(&value);
        content.push_str(&format!("{}={}\n", key, escaped_value));
    }

    std::fs::write(dotenv_path, &content)
        .context("Impossible d'écrire le fichier .env")?;

    // Effacer le contenu de la mémoire après écriture
    // (le fichier sur disque contient les secrets en clair — à utiliser avec précaution)
    drop(content);

    eprintln!(
        "{} Fichier .env créé. {}",
        "✓".green(),
        "Ajoutez .env à votre .gitignore !".yellow().bold()
    );

    Ok(())
}

/// Échappe une valeur pour le format .env
/// Les valeurs avec des espaces, guillemets ou caractères spéciaux sont mises entre guillemets
fn escape_dotenv_value(value: &str) -> String {
    if value.chars().any(|c| matches!(c, ' ' | '"' | '\'' | '\\' | '\n' | '$' | '`')) {
        // Mettre entre guillemets doubles et échapper les guillemets internes
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value.to_string()
    }
}
