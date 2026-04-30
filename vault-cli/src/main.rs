mod commands;
mod password;

use anyhow::{Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

/// SecureVault — Gestionnaire de secrets chiffrés
///
/// Les attributs `derive` de clap génèrent automatiquement :
/// - Le parsing des arguments
/// - L'affichage de l'aide (`--help`)
/// - La validation des entrées
#[derive(Parser)]
#[command(
    name = "vault",
    version = "1.0",
    about = "Gestionnaire de secrets chiffrés",
    long_about = "SecureVault chiffre vos secrets avec AES-256-GCM.\n\
                  Le mot de passe maître n'est jamais stocké sur disque."
)]
struct Cli {
    /// Chemin vers le fichier vault (défaut : ~/.config/securevault/vault.db)
    #[arg(
        short,
        long,
        default_value_os_t = default_vault_path(),
        global = true // disponible pour toutes les sous-commandes
    )]
    vault: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

/// Toutes les sous-commandes disponibles
#[derive(Subcommand)]
enum Commands {
    /// Initialise un nouveau vault vide
    Init,

    /// Ajoute ou met à jour un secret
    Set {
        /// Nom du secret (ex: DATABASE_URL)
        key: String,

        /// Valeur du secret. Si omis, sera demandé de façon sécurisée
        #[arg(short, long)]
        value: Option<String>,

        /// Tags optionnels (ex: --tag prod --tag database)
        #[arg(short, long, action = clap::ArgAction::Append)]
        tag: Vec<String>,

        /// Date d'expiration (format: YYYY-MM-DD)
        #[arg(short, long)]
        expires: Option<String>,
    },

    /// Récupère la valeur d'un secret
    Get {
        /// Nom du secret à récupérer
        key: String,
    },

    /// Supprime un secret du vault
    Delete {
        /// Nom du secret à supprimer
        key: String,
    },

    /// Liste tous les secrets (noms uniquement, pas les valeurs)
    List {
        /// Filtrer par tag
        #[arg(short, long)]
        tag: Option<String>,
    },

    /// Change le mot de passe maître
    Rotate,

    /// Affiche le journal d'audit
    Audit {
        /// Afficher seulement les N dernières entrées
        #[arg(short, long)]
        last: Option<usize>,

        /// Filtrer par type d'opération (init, set, get, delete, list, rotate)
        #[arg(short, long)]
        operation: Option<String>,

        /// Filtrer par clé de secret
        #[arg(short, long)]
        key: Option<String>,
    },
}

fn default_vault_path() -> PathBuf {
    // Utiliser $HOME/.config/securevault/vault.db si possible
    // Sinon, utiliser le répertoire courant
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("securevault")
        .join("vault.db")
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Gestion globale des erreurs avec contexte coloré
    let result = match cli.command {
        Commands::Init => commands::cmd_init(&cli.vault),
        Commands::Set { key, value, tag, expires } => {
            commands::cmd_set(&cli.vault, &key, value, tag, expires)
        }
        Commands::Get { key } => commands::cmd_get(&cli.vault, &key),
        Commands::Delete { key } => commands::cmd_delete(&cli.vault, &key),
        Commands::List { tag } => commands::cmd_list(&cli.vault, tag),
        Commands::Rotate => commands::cmd_rotate(&cli.vault),
        Commands::Audit { last, operation, key } => {
            commands::cmd_audit(&cli.vault, last, operation, key)
        }
    };

    if let Err(e) = result {
        eprintln!("{} {}", "Erreur :".red().bold(), e);
        std::process::exit(1);
    }

    Ok(())
}