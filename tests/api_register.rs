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
        r#"{"name": "Nouveau", "email": "Nouveau@Test.FR", "password": "motdepasse"}"#,
        &[],
    )
    .await;

    assert_eq!(response.status, StatusCode::CREATED);
    assert!(response.body["user_id"].is_string());

    let stored = state
        .users
        .find_by_email("nouveau@test.fr")
        .await
        .unwrap()
        .expect("utilisateur en base");
    assert!(stored.password_hash.starts_with("$argon2id$"));
    assert_eq!(stored.roles, vec!["user".to_string()]);
    assert_eq!(stored.name, "Nouveau");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn roles_du_body_ignores() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Pirate", "email": "pirate@test.fr", "password": "motdepasse", "roles": {"portail": "admin"}, "is_super_admin": true}"#,
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
        r#"{"name": "Double", "email": "Double@Test.FR", "password": "motdepasse"}"#,
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
        r#"{"name": "X", "email": "pas-un-email", "password": "motdepasse"}"#,
        r#"{"name": "X", "email": "ok@test.fr", "password": "court"}"#,
        r#"{"name": "X", "email": "ok@test.fr"}"#,
        r#"{"email": "ok@test.fr", "password": "motdepasse"}"#,
        r#"{"name": "  ", "email": "ok2@test.fr", "password": "motdepasse"}"#,
        "pas du json",
    ] {
        let response = post_json(router(state.clone()), "/register", body, &[]).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "payload : {body}");
        assert_eq!(response.body["error"], "bad_request");
    }

    db.drop().await.unwrap();
}

#[tokio::test]
async fn inscription_cree_un_compte_en_attente_de_validation() {
    use ch_api_authenticator::domain::user::AccountStatus;

    let db = test_db().await;
    let state = test_state(&db).await;

    let response = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Attente", "email": "attente@test.fr", "password": "motdepasse"}"#,
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED);

    let stored = state
        .users
        .find_by_email("attente@test.fr")
        .await
        .unwrap()
        .expect("utilisateur en base");
    assert_eq!(stored.status, AccountStatus::PendingValidation);

    db.drop().await.unwrap();
}
