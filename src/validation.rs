//! Validation partagée des requêtes entrantes (crate `validator`), alignée
//! avec les règles front des composants Input de CH-UI-Library : une règle de
//! validation par type de champ (email, longueur de mot de passe…).

use crate::error::AppError;
use validator::{Validate, ValidationErrors};

/// Taille minimale du mot de passe (alignée avec `PASSWORD_MIN_LENGTH` côté front).
pub const PASSWORD_MIN_CHARS: u64 = 8;

/// Valide une requête dérivant `Validate` et mappe l'échec sur `400`.
pub fn check<T: Validate>(value: &T) -> Result<(), AppError> {
    value
        .validate()
        .map_err(|errors| AppError::Validation(format_errors(&errors)))
}

fn format_errors(errors: &ValidationErrors) -> String {
    errors
        .field_errors()
        .values()
        .flat_map(|field_errors| field_errors.iter())
        .map(|e| e.message.as_deref().unwrap_or("champ invalide").to_string())
        .collect::<Vec<_>>()
        .join(" ; ")
}
