// Déclarer les modules — Rust cherche vault-core/src/nom_module.rs
pub mod crypto;
pub mod error;
pub mod types;

// pub fn add(left: u64, right: u64) -> u64 {
//     left + right
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }

// Ré-exporter les types les plus utilisés pour simplifier les imports côté appelant.
// Au lieu de `vault_core::types::VaultEntry`, on peut écrire `vault_core::VaultEntry`.
pub use error::{VaultError, VaultResult};
pub use types::{Secret, Vault, VaultEntry};
pub mod storage;
