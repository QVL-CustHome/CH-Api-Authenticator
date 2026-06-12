use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

pub fn hash(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

#[allow(dead_code)]
pub fn verify(password: &str, stored_hash: &str) -> bool {
    PasswordHash::new(stored_hash)
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_produit_de_l_argon2id_avec_sel_aleatoire() {
        let h1 = hash("mon-mot-de-passe").unwrap();
        let h2 = hash("mon-mot-de-passe").unwrap();
        assert!(h1.starts_with("$argon2id$"));
        assert_ne!(
            h1, h2,
            "deux hashes du même mot de passe doivent différer (sel)"
        );
    }

    #[test]
    fn verify_accepte_le_bon_mot_de_passe() {
        let h = hash("Corr3ct-H0rse!").unwrap();
        assert!(verify("Corr3ct-H0rse!", &h));
    }

    #[test]
    fn verify_rejette_mauvais_mot_de_passe_et_hash_corrompu() {
        let h = hash("Corr3ct-H0rse!").unwrap();
        assert!(!verify("mauvais", &h));
        assert!(!verify("Corr3ct-H0rse!", "pas-un-hash"));
    }
}
