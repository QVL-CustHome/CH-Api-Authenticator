use ch_auth_jwt::{Claims, JwtCodec, JwtErrorKind, extract_token, unix_now};
use std::time::Duration;

const SECRET: &str = "secret-de-test-us09-suffisamment-long-1234";

#[test]
fn token_hs256_emis_porte_les_claims_canoniques() {
    let codec = JwtCodec::from_secret(SECRET);
    let token = codec
        .issue(
            "507f1f77bcf86cd799439011",
            vec!["admin".to_string(), "user".to_string()],
            Some("10.0.0.4".to_string()),
            Duration::from_secs(900),
        )
        .unwrap();

    let claims = codec.decode(&token).unwrap();

    assert_eq!(claims.sub, "507f1f77bcf86cd799439011");
    assert_eq!(claims.roles, vec!["admin".to_string(), "user".to_string()]);
    assert_eq!(claims.ip.as_deref(), Some("10.0.0.4"));
    assert_eq!(claims.exp - claims.iat, 900);
}

#[test]
fn ttl_respecte_la_duree_demandee() {
    let codec = JwtCodec::from_secret(SECRET);
    let avant = unix_now();
    let token = codec
        .issue("u", Vec::new(), None, Duration::from_secs(3600))
        .unwrap();
    let claims = codec.decode(&token).unwrap();

    assert!(claims.iat >= avant);
    assert_eq!(claims.exp - claims.iat, 3600);
}

#[test]
fn token_expire_est_rejete() {
    let codec = JwtCodec::from_secret(SECRET);
    let now = unix_now();
    let claims = Claims::new("u", Vec::new(), None, now - 7200, now - 3600);
    let token = codec.encode(&claims).unwrap();

    let erreur = codec.decode(&token).unwrap_err();
    assert_eq!(erreur.kind(), &JwtErrorKind::ExpiredSignature);
}

#[test]
fn token_signe_avec_un_autre_secret_est_rejete() {
    let emetteur = JwtCodec::from_secret("un-secret-etranger-aussi-long-mais-faux!");
    let verificateur = JwtCodec::from_secret(SECRET);
    let token = emetteur
        .issue("u", Vec::new(), None, Duration::from_secs(900))
        .unwrap();

    let erreur = verificateur.decode(&token).unwrap_err();
    assert_eq!(erreur.kind(), &JwtErrorKind::InvalidSignature);
}

const COOKIE_NAME: &str = "auth_token";

#[test]
fn extraction_depuis_header_bearer() {
    let extrait = extract_token(Some("Bearer abc.def.ghi"), None, COOKIE_NAME);
    assert_eq!(extrait.as_deref(), Some("abc.def.ghi"));
}

#[test]
fn extraction_replie_sur_le_cookie_quand_header_absent() {
    let cookies = format!("{COOKIE_NAME}=abc.def.ghi; autre=1");
    let extrait = extract_token(None, Some(&cookies), COOKIE_NAME);
    assert_eq!(extrait.as_deref(), Some("abc.def.ghi"));
}

#[test]
fn extraction_replie_sur_le_cookie_quand_header_non_bearer() {
    let cookies = format!("{COOKIE_NAME}=cookie.jwt.value");
    let extrait = extract_token(Some("Basic xyz"), Some(&cookies), COOKIE_NAME);
    assert_eq!(extrait.as_deref(), Some("cookie.jwt.value"));
}

#[test]
fn extraction_privilegie_le_header_bearer_sur_le_cookie() {
    let cookies = format!("{COOKIE_NAME}=du-cookie");
    let extrait = extract_token(Some("Bearer du-header"), Some(&cookies), COOKIE_NAME);
    assert_eq!(extrait.as_deref(), Some("du-header"));
}

#[test]
fn extraction_sans_header_ni_cookie_renvoie_none() {
    assert_eq!(extract_token(None, None, COOKIE_NAME), None);
}
