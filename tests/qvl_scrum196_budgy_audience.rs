use ch_api_authenticator::config::TokenConfig;
use ch_api_authenticator::domain::role::Portal;
use ch_api_authenticator::domain::user::User;
use ch_api_authenticator::services::jwt::JwtService;
use mongodb::bson::oid::ObjectId;

const SECRET: &str = "un-secret-de-test-suffisamment-long!!!!!";
const ISSUER_ATTENDU: &str = "ch-api-authenticator";
const AUDIENCE_DRIVE: &str = "ch-api-drive";
const AUDIENCE_BUDGY: &str = "ch-api-budgy";

fn token_config() -> TokenConfig {
    TokenConfig {
        cookie_domain: None,
        ttl_minutes: 15,
        cookie_name: "ch_token".to_string(),
        cookie_secure: false,
        refresh_ttl_days: 7,
        refresh_cookie_name: "ch_refresh".to_string(),
        issuer: ISSUER_ATTENDU.to_string(),
        audience_drive: AUDIENCE_DRIVE.to_string(),
        audience_budgy: AUDIENCE_BUDGY.to_string(),
    }
}

fn service() -> JwtService {
    JwtService::new(SECRET, &token_config())
}

fn user_avec_roles(roles: &[&str]) -> User {
    let mut user = User::new(
        "martin@test.fr",
        "$argon2id$hash".to_string(),
        roles.iter().map(|r| r.to_string()).collect(),
    );
    user.id = Some(ObjectId::new());
    user
}

fn aud_du_token(role: &str) -> Vec<String> {
    let service = service();
    let token = service
        .issue(&user_avec_roles(&[role]), None)
        .expect("emission du token");
    service
        .validate(&token)
        .expect("decodage du token emis")
        .aud
}

#[test]
fn ac1_token_utilisateur_budgy_porte_audience_ch_api_budgy() {
    let aud = aud_du_token("budgy");

    assert!(aud.iter().any(|value| value == AUDIENCE_BUDGY));
}

#[test]
fn ac2_token_budgy_conserve_issuer_authenticator() {
    let service = service();
    let token = service
        .issue(&user_avec_roles(&["budgy"]), None)
        .expect("emission du token budgy");

    let claims = service.validate(&token).expect("decodage du token emis");

    assert_eq!(claims.iss, ISSUER_ATTENDU);
}

#[test]
fn ac3_token_drive_ne_fuit_pas_audience_budgy() {
    let aud = aud_du_token("drive");

    assert!(!aud.iter().any(|value| value == AUDIENCE_BUDGY));
}

#[test]
fn ac3_token_admin_ne_fuit_pas_audience_budgy() {
    let aud = aud_du_token("admin");

    assert!(!aud.iter().any(|value| value == AUDIENCE_BUDGY));
}

#[test]
fn ac3_token_home_ne_fuit_pas_audience_budgy() {
    let aud = aud_du_token("home");

    assert!(!aud.iter().any(|value| value == AUDIENCE_BUDGY));
}

#[test]
fn ac4_token_drive_conserve_audience_ch_api_drive() {
    let aud = aud_du_token("drive");

    assert!(aud.iter().any(|value| value == AUDIENCE_DRIVE));
}

#[test]
fn ac4_token_admin_nembarque_aucune_audience() {
    let aud = aud_du_token("admin");

    assert!(aud.is_empty());
}

#[test]
fn ac4_token_home_nembarque_aucune_audience() {
    let aud = aud_du_token("home");

    assert!(aud.is_empty());
}

#[test]
fn ac4_token_budgy_nembarque_pas_audience_drive() {
    let aud = aud_du_token("budgy");

    assert!(!aud.iter().any(|value| value == AUDIENCE_DRIVE));
}

#[test]
fn ac1_ac4_utilisateur_drive_et_budgy_cumule_les_deux_audiences() {
    let service = service();
    let token = service
        .issue(&user_avec_roles(&["drive", "budgy"]), None)
        .expect("emission du token multi-roles");

    let claims = service.validate(&token).expect("decodage du token emis");

    assert!(claims.aud.iter().any(|value| value == AUDIENCE_DRIVE));
    assert!(claims.aud.iter().any(|value| value == AUDIENCE_BUDGY));
}

#[test]
fn ac5_header_portail_budgy_resout_le_portail_budgy() {
    assert_eq!(
        Portal::from_portal_header("portail_budgy"),
        Some(Portal::Budgy)
    );
}

#[test]
fn ac5_portail_budgy_fait_partie_des_portails_connus() {
    assert!(Portal::ALL.contains(&Portal::Budgy));
}

#[test]
fn ac5_portail_budgy_porte_le_role_budgy() {
    assert_eq!(Portal::Budgy.role_name(), "budgy");
}

#[test]
fn ac5_header_inconnu_ne_resout_aucun_portail() {
    assert_eq!(Portal::from_portal_header("portail_inconnu"), None);
}

#[test]
fn ac5_ensemble_des_portails_connus_inclut_budgy_sans_perdre_les_existants() {
    let connus: Vec<&'static str> = Portal::ALL
        .iter()
        .map(|portal| portal.role_name())
        .collect();

    assert!(connus.contains(&"admin"));
    assert!(connus.contains(&"drive"));
    assert!(connus.contains(&"home"));
    assert!(connus.contains(&"budgy"));
    assert_eq!(connus.len(), 4);
}

#[test]
fn ac5_chaque_portail_connu_porte_un_role_non_vide() {
    for portal in Portal::ALL {
        assert!(!portal.role_name().is_empty());
    }
}

#[test]
fn f1_header_portail_valeur_inconnue_typo_budgy_ne_resout_aucun_portail() {
    assert_eq!(Portal::from_portal_header("portail_bugdy"), None);
}

#[test]
fn f1_headers_portail_valides_resolvent_chacun_leur_portail() {
    assert_eq!(
        Portal::from_portal_header("portail_admin"),
        Some(Portal::Admin)
    );
    assert_eq!(
        Portal::from_portal_header("portail_drive"),
        Some(Portal::Drive)
    );
    assert_eq!(
        Portal::from_portal_header("portail_home"),
        Some(Portal::Home)
    );
    assert_eq!(
        Portal::from_portal_header("portail_budgy"),
        Some(Portal::Budgy)
    );
}
