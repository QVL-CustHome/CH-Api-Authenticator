use crate::error::AppError;
use validator::{Validate, ValidationErrors};

pub const PASSWORD_MIN_CHARS: u64 = 8;

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
