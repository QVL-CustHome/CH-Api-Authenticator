mod common;

use axum::http::StatusCode;
use ch_api_authenticator::services::client_ip::CLIENT_IP_HEADER;
use ch_api_authenticator::routes::router;
use common::*;
use mongodb::bson::doc;
use std::collections::HashMap;

const LOGIN_BODY: &str = r#"{"email": "martin@test.fr", "password": "Bon-Mot-De-Passe1"}"#;
const WHITELIST_BODY: &str = r#"{"email": "secure@test.fr", "password": "Bon-Mot-De-Passe1"}"#;

#[tokio::test]
async fn login_valide_200_token_et_cookie() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", roles(&[("portail_a", "admin")])).await;

    let response = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "Martin@Test.FR", "password": "Bon-Mot-De-Passe1"}"#,
        &[],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["token_type"], "Bearer");
    assert_eq!(response.body["expires_in"], 15 * 60);

    let claims = state
        .jwt
        .validate(response.body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims.roles, vec!["admin".to_string()]);
    assert_eq!(claims.ip, None);

    let cookie = response.set_cookie.expect("Set-Cookie présent");
    assert!(cookie.starts_with("ch_token="));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Max-Age=900"));
    assert!(!cookie.contains("Secure"));

    db.drop().await.unwrap();
}

#[tokio::test]
async fn cookie_secure_quand_configure() {
    let db = test_db().await;
    let state = test_state_with(&db, true, HashMap::new()).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;

    let response = post_json(router(state), "/login", LOGIN_BODY, &[]).await;
    assert!(response.set_cookie.unwrap().contains("; Secure"));

    db.drop().await.unwrap();
}

#[tokio::test]
async fn reponse_401_strictement_identique_email_inconnu_ou_mdp_faux() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;

    let inconnu = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "inconnu@test.fr", "password": "peu-importe"}"#,
        &[],
    )
    .await;
    let mauvais_mdp = post_json(
        router(state),
        "/login",
        r#"{"email": "martin@test.fr", "password": "mauvais-mot-de-passe"}"#,
        &[],
    )
    .await;

    assert_eq!(inconnu.status, StatusCode::UNAUTHORIZED);
    assert_eq!(mauvais_mdp.status, StatusCode::UNAUTHORIZED);
    assert_eq!(inconnu.body, mauvais_mdp.body);
    assert_eq!(inconnu.set_cookie, None);
    assert_eq!(mauvais_mdp.set_cookie, None);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn whitelist_ip_exacte_200_avec_claim_ip() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_whitelist_user(&state, "secure@test.fr", &["10.1.2.3", "192.168.0.0/16"]).await;

    let response = post_json(
        router(state.clone()),
        "/login",
        WHITELIST_BODY,
        &[(CLIENT_IP_HEADER, "10.1.2.3")],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    let claims = state
        .jwt
        .validate(response.body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims.ip.as_deref(), Some("10.1.2.3"));

    db.drop().await.unwrap();
}

#[tokio::test]
async fn whitelist_ip_dans_cidr_200() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_whitelist_user(&state, "secure@test.fr", &["10.1.2.3", "192.168.0.0/16"]).await;

    let response = post_json(
        router(state),
        "/login",
        WHITELIST_BODY,
        &[(CLIENT_IP_HEADER, "192.168.42.7")],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn whitelist_ip_hors_liste_ou_absente_403_device() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_whitelist_user(&state, "secure@test.fr", &["10.1.2.3"]).await;

    let hors_liste = post_json(
        router(state.clone()),
        "/login",
        WHITELIST_BODY,
        &[(CLIENT_IP_HEADER, "8.8.8.8")],
    )
    .await;
    let sans_header = post_json(router(state.clone()), "/login", WHITELIST_BODY, &[]).await;

    let mauvais_mdp = post_json(
        router(state),
        "/login",
        r#"{"email": "secure@test.fr", "password": "mauvais"}"#,
        &[(CLIENT_IP_HEADER, "10.1.2.3")],
    )
    .await;

    assert_eq!(hors_liste.status, StatusCode::FORBIDDEN);
    assert_eq!(hors_liste.body["error"], "device_not_allowed");
    assert_eq!(sans_header.status, StatusCode::FORBIDDEN);
    assert_eq!(sans_header.body["error"], "device_not_allowed");
    assert_eq!(mauvais_mdp.status, StatusCode::UNAUTHORIZED);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn login_sans_whitelist_memorise_l_ip() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;

    let response = post_json(
        router(state.clone()),
        "/login",
        LOGIN_BODY,
        &[(CLIENT_IP_HEADER, "203.0.113.7")],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    let user = state
        .users
        .find_by_email("martin@test.fr")
        .await
        .unwrap()
        .unwrap();
    assert!(!user.whitelist_only);
    assert_eq!(user.allowed_ips, vec!["203.0.113.7".to_string()]);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn user_sans_whitelist_non_impacte() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;

    let response = post_json(router(state.clone()), "/login", LOGIN_BODY, &[]).await;

    assert_eq!(response.status, StatusCode::OK);
    let claims = state
        .jwt
        .validate(response.body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims.ip, None);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn payload_invalide_400() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = post_json(router(state), "/login", "pas du json", &[]).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.body["error"], "bad_request");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn login_compte_en_attente_refuse_403() {
    let db = test_db().await;
    let state = test_state(&db).await;

    post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Attente", "email": "attente@test.fr", "password": "Bon-Mot-De-Passe1"}"#,
        &[],
    )
    .await;

    let response = post_json(
        router(state),
        "/login",
        r#"{"email": "attente@test.fr", "password": "Bon-Mot-De-Passe1"}"#,
        &[],
    )
    .await;

    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.body["error"], "account_pending");
    assert_eq!(response.set_cookie, None);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn login_compte_desactive_refuse_403() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let user = seed_user(&state, "off@test.fr", HashMap::new()).await;

    db.collection::<mongodb::bson::Document>("users")
        .update_one(
            doc! { "_id": user.id.unwrap() },
            doc! { "$set": { "status": "disabled" } },
        )
        .await
        .unwrap();

    let response = post_json(
        router(state),
        "/login",
        r#"{"email": "off@test.fr", "password": "Bon-Mot-De-Passe1"}"#,
        &[],
    )
    .await;

    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.body["error"], "account_disabled");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn login_apres_validation_200() {
    let db = test_db().await;
    let state = test_state(&db).await;

    post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Valide", "email": "valide@test.fr", "password": "Bon-Mot-De-Passe1"}"#,
        &[],
    )
    .await;
    activate_user(&db, "valide@test.fr").await;

    let response = post_json(
        router(state),
        "/login",
        r#"{"email": "valide@test.fr", "password": "Bon-Mot-De-Passe1"}"#,
        &[],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert!(response.body["access_token"].is_string());

    db.drop().await.unwrap();
}
