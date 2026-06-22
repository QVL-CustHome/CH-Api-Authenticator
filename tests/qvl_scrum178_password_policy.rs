use ch_api_authenticator::validation::{PASSWORD_MIN_CHARS, validate_password_strength};

fn rejection_code(password: &str) -> String {
    validate_password_strength(password)
        .expect_err("mot de passe attendu rejeté")
        .code
        .to_string()
}

#[test]
fn longueur_minimale_est_douze() {
    assert_eq!(PASSWORD_MIN_CHARS, 12);
}

#[test]
fn mot_de_passe_trop_court_rejete_meme_avec_les_quatre_classes() {
    let password = "Ab1!cdef";
    assert!(password.chars().count() < PASSWORD_MIN_CHARS as usize);
    assert_eq!(rejection_code(password), "password_strength");
}

#[test]
fn mot_de_passe_sans_majuscule_rejete() {
    assert_eq!(rejection_code("abcdef1234!@"), "password_strength");
}

#[test]
fn mot_de_passe_sans_minuscule_rejete() {
    assert_eq!(rejection_code("ABCDEF1234!@"), "password_strength");
}

#[test]
fn mot_de_passe_sans_chiffre_rejete() {
    assert_eq!(rejection_code("Abcdefghij!@"), "password_strength");
}

#[test]
fn mot_de_passe_sans_caractere_special_rejete() {
    assert_eq!(rejection_code("Abcdefghij12"), "password_strength");
}

#[test]
fn mot_de_passe_long_avec_les_quatre_classes_et_hors_blocklist_est_accepte() {
    let password = "Zorglub-Vortex42!";
    assert!(password.chars().count() >= PASSWORD_MIN_CHARS as usize);
    assert!(validate_password_strength(password).is_ok());
}

#[test]
fn mot_de_passe_commun_court_rejete() {
    let result = validate_password_strength("password");
    assert!(result.is_err());
}

#[test]
fn mot_de_passe_commun_en_majuscules_rejete() {
    let result = validate_password_strength("PASSWORD");
    assert!(result.is_err());
}

fn satisfait_la_complexite(password: &str) -> bool {
    let normalise = password.trim();
    normalise.chars().count() >= PASSWORD_MIN_CHARS as usize
        && normalise.chars().any(|c| c.is_ascii_uppercase())
        && normalise.chars().any(|c| c.is_ascii_lowercase())
        && normalise.chars().any(|c| c.is_ascii_digit())
        && normalise.chars().any(|c| !c.is_ascii_alphanumeric())
}

#[test]
fn mdp_compromis_welcome2022_passe_la_complexite_mais_rejete_comme_compromis() {
    let password = "Welcome2022!";
    assert!(satisfait_la_complexite(password));
    assert_eq!(rejection_code(password), "password_compromised");
}

#[test]
fn mdp_compromis_password2023_passe_la_complexite_mais_rejete_comme_compromis() {
    let password = "Password2023!!";
    assert!(satisfait_la_complexite(password));
    assert_eq!(rejection_code(password), "password_compromised");
}

#[test]
fn mdp_compromis_bienvenue2024_passe_la_complexite_mais_rejete_comme_compromis() {
    let password = "Bienvenue2024@@";
    assert!(satisfait_la_complexite(password));
    assert_eq!(rejection_code(password), "password_compromised");
}

#[test]
fn mdp_compromis_normalise_avec_espaces_autour_rejete_comme_compromis() {
    let password = "  Welcome2022!  ";
    assert!(satisfait_la_complexite(password));
    assert_eq!(rejection_code(password), "password_compromised");
}

#[test]
fn mdp_compromis_normalise_variante_de_casse_rejete_comme_compromis() {
    let password = "WELCOMe2022!";
    assert!(satisfait_la_complexite(password));
    assert_eq!(rejection_code(password), "password_compromised");
}
