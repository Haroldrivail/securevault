use anyhow::{Context, Result};

/// Demande le mot de passe maître sans afficher les caractères saisis.
///
/// `rpassword` désactive l'écho du terminal avant de lire stdin,
/// puis le réactive après, même si le programme est interrompu (Ctrl+C).
///
/// # Sécurité
/// Le mot de passe est stocké dans un `String` en RAM.
/// Rust ne garantit pas l'effacement de la mémoire à la libération (le
/// compilateur peut optimiser). Pour une sécurité renforcée, on pourrait
/// utiliser la crate `secrecy` qui efface les bytes à la destruction.
pub fn prompt_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt)
        .context("Impossible de lire le mot de passe")
}

/// Demande le mot de passe deux fois et vérifie qu'ils correspondent.
/// Utilisé lors de l'initialisation et la rotation.
pub fn prompt_password_confirm() -> Result<String> {
    let password = prompt_password("Mot de passe maître : ")?;

    if password.is_empty() {
        anyhow::bail!("Le mot de passe ne peut pas être vide");
    }

    if password.len() < 8 {
        anyhow::bail!("Le mot de passe doit faire au moins 8 caractères");
    }

    let confirm = prompt_password("Confirmez le mot de passe : ")?;

    if password != confirm {
        anyhow::bail!("Les mots de passe ne correspondent pas");
    }

    Ok(password)
}