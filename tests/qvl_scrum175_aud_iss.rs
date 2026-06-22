use ch_api_authenticator::config::TokenConfig;
use ch_api_authenticator::domain::user::User;
use ch_api_authenticator::services::jwt::JwtService;
use mongodb::bson::oid::ObjectId;

const SECRET: &str = "un-secret-de-test-suffisamment-long!!!!!";
const ISSUER_ATTENDU: &str = "ch-api-authenticator";
const AUDIENCE_DRIVE: &str = "ch-api-drive";

fn token_config() -> TokenConfig {
    TokenConfig {
        ttl_minutes: 15,
        cookie_name: "ch_token".to_string(),
        cookie_secure: false,
        refresh_ttl_days: 7,
        refresh_cookie_name: "ch_refresh".to_string(),
        issuer: ISSUER_ATTENDU.to_string(),
        audience_drive: AUDIENCE_DRIVE.to_string(),
    }
}

fn service() -> JwtService {
    JwtService::new(SECRET, &token_config())
}

fn user_avec_role(role: &str) -> User {
    let mut user = User::new(
        "martin@test.fr",
        "$argon2id$hash".to_string(),
        vec![role.to_string()],
    );
    user.id = Some(ObjectId::new());
    user
}

#[test]
fn token_pour_utilisateur_drive_porte_aud_drive_et_iss_authenticator() {
    let service = service();
    let token = service
        .issue(&user_avec_role("drive"), None)
        .expect("emission du token drive");

    let claims = service.validate(&token).expect("decodage du token emis");

    assert!(claims.aud.iter().any(|value| value == AUDIENCE_DRIVE));
    assert_eq!(claims.iss, ISSUER_ATTENDU);
}

#[test]
fn token_pour_utilisateur_non_drive_nembarque_pas_aud_drive() {
    let service = service();
    let token = service
        .issue(&user_avec_role("admin"), None)
        .expect("emission du token admin");

    let claims = service.validate(&token).expect("decodage du token emis");

    assert!(!claims.aud.iter().any(|value| value == AUDIENCE_DRIVE));
}

#[test]
fn validate_interne_accepte_un_token_admin_sans_aud_drive() {
    let service = service();
    let token = service
        .issue(&user_avec_role("admin"), None)
        .expect("emission du token admin");

    let claims = service.validate(&token);

    assert!(claims.is_ok());
}

#[test]
fn validate_interne_accepte_un_token_home_sans_aud_drive() {
    let service = service();
    let token = service
        .issue(&user_avec_role("home"), None)
        .expect("emission du token home");

    let claims = service.validate(&token);

    assert!(claims.is_ok());
}
