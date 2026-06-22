use crate::error::AppError;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::LazyLock;
use validator::{Validate, ValidationError, ValidationErrors};

pub const PASSWORD_MIN_CHARS: u64 = 12;

static COMPROMISED_PASSWORDS: LazyLock<HashSet<String>> = LazyLock::new(|| {
    include_str!("../data/common-passwords-top10k.txt")
        .lines()
        .chain(include_str!("../data/compromised-complex-passwords.txt").lines())
        .map(normalize_password)
        .filter(|entry| !entry.is_empty())
        .collect()
});

fn normalize_password(value: &str) -> String {
    value.trim().to_lowercase()
}

fn is_compromised(value: &str) -> bool {
    COMPROMISED_PASSWORDS.contains(&normalize_password(value))
}

pub fn validate_password_strength(value: &str) -> Result<(), ValidationError> {
    let length_ok = value.chars().count() >= PASSWORD_MIN_CHARS as usize;
    let has_upper = value.chars().any(|c| c.is_uppercase());
    let has_lower = value.chars().any(|c| c.is_lowercase());
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_special = value.chars().any(|c| !c.is_alphanumeric());

    if !(length_ok && has_upper && has_lower && has_digit && has_special) {
        let mut error = ValidationError::new("password_strength");
        error.message = Some(Cow::Borrowed(
            "le mot de passe doit contenir au moins 12 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial",
        ));
        return Err(error);
    }

    if is_compromised(value) {
        let mut error = ValidationError::new("password_compromised");
        error.message = Some(Cow::Borrowed(
            "ce mot de passe est trop courant ou compromis : choisissez-en un autre",
        ));
        return Err(error);
    }

    Ok(())
}

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
