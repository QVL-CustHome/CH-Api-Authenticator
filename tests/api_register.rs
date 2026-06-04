//! US-02 — Inscription : validation, Argon2id, rôles par défaut, 201/409/400.

mod common;

use axum::http::StatusCode;
use ch_api_authenticator::routes::router;
use common::*;
use std::collections::HashMap;

#[tokio::test]
async fn inscription_valide_201_avec_hash_et_roles_par_defaut() {
    let db = test_db().await;
    let state = test_state_with(&db, false, roles(&[("portail_test", "user")])).await;

    let response = post_json(
        router(state.clone()),
        "/register",
        r#"{"email": "Nouveau@Test.FR", "password": "motdepasse"}"#,
        &[],
    )
    .await;

    assert_eq!(response.status, StatusCode::CREATED);
    assert!(response.body["user_id"].is_string());

    // Vérifications en base : email normalisé, hash Argon2id, rôles de la config.
    let stored = state
        .users
        .find_by_email("nouveau@test.fr")
        .await
        .unwrap()
        .expect("utilisateur en base");
    assert!(stored.password_hash.starts_with("$argon2id$"));
    assert_eq!(
        stored.roles.get("portail_test").map(String::as_str),
        Some("user")
    );
    assert!(!stored.is_super_admin);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn roles_du_body_ignores() {
    let db = test_db().await;
    let state = test_state(&db).await;

    // Tentative d'escalade : roles/is_super_admin dans le body → champs inconnus ignorés.
    let response = post_json(
        router(state.clone()),
        "/register",
        r#"{"email": "pirate@test.fr", "password": "motdepasse", "roles": {"portail": "admin"}, "is_super_admin": true}"#,
        &[],
    )
    .await;

    assert_eq!(response.status, StatusCode::CREATED);
    let stored = state
        .users
        .find_by_email("pirate@test.fr")
        .await
        .unwrap()
        .unwrap();
    assert!(stored.roles.is_empty());
    assert!(!stored.is_super_admin);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn email_deja_utilise_409() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "double@test.fr", HashMap::new()).await;

    let response = post_json(
        router(state),
        "/register",
        r#"{"email": "Double@Test.FR", "password": "motdepasse"}"#,
        &[],
    )
    .await;

    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.body["error"], "conflict");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn payloads_invalides_400() {
    let db = test_db().await;
    let state = test_state(&db).await;

    for body in [
        r#"{"email": "pas-un-email", "password": "motdepasse"}"#, // email invalide
        r#"{"email": "ok@test.fr", "password": "court"}"#,        // mdp < 8
        r#"{"email": "ok@test.fr"}"#,                             // champ manquant
        "pas du json",                                            // JSON malformé
    ] {
        let response = post_json(router(state.clone()), "/register", body, &[]).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "payload : {body}");
        assert_eq!(response.body["error"], "bad_request");
    }

    db.drop().await.unwrap();
}
