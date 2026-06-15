use crate::error::AppError;
use std::borrow::Cow;
use validator::{Validate, ValidationError, ValidationErrors};

pub const PASSWORD_MIN_CHARS: u64 = 8;

pub fn validate_password_strength(value: &str) -> Result<(), ValidationError> {
    let length_ok = value.chars().count() >= PASSWORD_MIN_CHARS as usize;
    let has_upper = value.chars().any(|c| c.is_uppercase());
    let has_lower = value.chars().any(|c| c.is_lowercase());
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_special = value.chars().any(|c| !c.is_alphanumeric());

    if length_ok && has_upper && has_lower && has_digit && has_special {
        return Ok(());
    }

    let mut error = ValidationError::new("password_strength");
    error.message = Some(Cow::Borrowed(
        "le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial",
    ));
    Err(error)
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
