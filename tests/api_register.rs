mod common;

use axum::http::StatusCode;
use ch_api_authenticator::domain::terms::CURRENT_TERMS_VERSION;
use ch_api_authenticator::routes::router;
use common::*;
use mongodb::bson::{DateTime, Document, doc};
use std::collections::HashMap;

fn register_body(name: &str, email: &str) -> String {
    format!(
        r#"{{"name": "{name}", "email": "{email}", "password": "{PASSWORD}", "accepted_terms_version": "{CURRENT_TERMS_VERSION}"}}"#
    )
}

#[tokio::test]
async fn inscription_valide_201_avec_hash_et_roles_par_defaut() {
    let db = test_db().await;
    let state = test_state_with(&db, false, roles(&[("portail_test", "user")])).await;

    let response = post_json(
        router(state.clone()),
        "/register",
        &register_body("Nouveau", "Nouveau@Test.FR"),
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
        &format!(
            r#"{{"name": "Pirate", "email": "pirate@test.fr", "password": "{PASSWORD}", "roles": {{"portail": "admin"}}, "is_super_admin": true, "accepted_terms_version": "{CURRENT_TERMS_VERSION}"}}"#
        ),
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
        &register_body("Double", "Double@Test.FR"),
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
        format!(
            r#"{{"name": "X", "email": "pas-un-email", "password": "Motdepasse1!", "accepted_terms_version": "{CURRENT_TERMS_VERSION}"}}"#
        ),
        format!(
            r#"{{"name": "X", "email": "ok@test.fr", "password": "court", "accepted_terms_version": "{CURRENT_TERMS_VERSION}"}}"#
        ),
        format!(
            r#"{{"name": "X", "email": "ok@test.fr", "accepted_terms_version": "{CURRENT_TERMS_VERSION}"}}"#
        ),
        format!(
            r#"{{"email": "ok@test.fr", "password": "Motdepasse1!", "accepted_terms_version": "{CURRENT_TERMS_VERSION}"}}"#
        ),
        format!(
            r#"{{"name": "  ", "email": "ok2@test.fr", "password": "Motdepasse1!", "accepted_terms_version": "{CURRENT_TERMS_VERSION}"}}"#
        ),
        "pas du json".to_string(),
    ] {
        let response = post_json(router(state.clone()), "/register", &body, &[]).await;
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
        &register_body("Attente", "attente@test.fr"),
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

#[tokio::test]
async fn inscription_sans_acceptation_422_terms_not_accepted() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = post_json(
        router(state.clone()),
        "/register",
        &format!(r#"{{"name": "Sans", "email": "sans@test.fr", "password": "{PASSWORD}"}}"#),
        &[],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response.body["error"], "terms_not_accepted");

    let stored = state.users.find_by_email("sans@test.fr").await.unwrap();
    assert!(stored.is_none());

    db.drop().await.unwrap();
}

#[tokio::test]
async fn inscription_version_vide_422_terms_not_accepted() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = post_json(
        router(state.clone()),
        "/register",
        &format!(
            r#"{{"name": "Vide", "email": "vide@test.fr", "password": "{PASSWORD}", "accepted_terms_version": ""}}"#
        ),
        &[],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response.body["error"], "terms_not_accepted");

    let stored = state.users.find_by_email("vide@test.fr").await.unwrap();
    assert!(stored.is_none());

    db.drop().await.unwrap();
}

#[tokio::test]
async fn inscription_version_non_conforme_422_terms_version_mismatch() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = post_json(
        router(state.clone()),
        "/register",
        &format!(
            r#"{{"name": "Vieux", "email": "vieux@test.fr", "password": "{PASSWORD}", "accepted_terms_version": "v0"}}"#
        ),
        &[],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response.body["error"], "terms_version_mismatch");

    let stored = state.users.find_by_email("vieux@test.fr").await.unwrap();
    assert!(stored.is_none());

    db.drop().await.unwrap();
}

#[tokio::test]
async fn inscription_valide_persiste_version_et_horodatage() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let before = DateTime::now().timestamp_millis();

    let response = post_json(
        router(state.clone()),
        "/register",
        &register_body("Preuve", "preuve@test.fr"),
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED);

    let stored = state
        .users
        .find_by_email("preuve@test.fr")
        .await
        .unwrap()
        .expect("utilisateur en base");
    assert_eq!(stored.terms_version.as_deref(), Some(CURRENT_TERMS_VERSION));
    let accepted_at = stored
        .terms_accepted_at
        .expect("horodatage d'acceptation persisté");
    assert!(accepted_at.timestamp_millis() >= before);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn horodatage_fourni_par_le_client_est_ignore() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let before = DateTime::now().timestamp_millis();

    let body = format!(
        r#"{{"name": "Menteur", "email": "menteur@test.fr", "password": "{PASSWORD}", "accepted_terms_version": "{CURRENT_TERMS_VERSION}", "terms_accepted_at": "2000-01-01T00:00:00Z"}}"#
    );
    let response = post_json(router(state.clone()), "/register", &body, &[]).await;
    assert_eq!(response.status, StatusCode::CREATED);

    let stored = state
        .users
        .find_by_email("menteur@test.fr")
        .await
        .unwrap()
        .expect("utilisateur en base");
    let accepted_at = stored
        .terms_accepted_at
        .expect("horodatage fixé côté serveur");
    assert!(accepted_at.timestamp_millis() >= before);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn user_legacy_sans_champs_cgu_reste_lisible() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let legacy = doc! {
        "name": "Legacy",
        "email": "legacy@test.fr",
        "password_hash": "$argon2id$legacy",
        "created_at": DateTime::now(),
        "updated_at": DateTime::now(),
    };
    db.collection::<Document>("users")
        .insert_one(legacy)
        .await
        .unwrap();

    let stored = state
        .users
        .find_by_email("legacy@test.fr")
        .await
        .unwrap()
        .expect("utilisateur legacy lisible");
    assert!(stored.terms_version.is_none());
    assert!(stored.terms_accepted_at.is_none());
    assert_eq!(stored.email, "legacy@test.fr");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn seule_la_version_courante_est_acceptee() {
    assert_eq!(CURRENT_TERMS_VERSION, "v1");

    let db = test_db().await;
    let state = test_state(&db).await;

    let acceptee = post_json(
        router(state.clone()),
        "/register",
        &register_body("Courante", "courante@test.fr"),
        &[],
    )
    .await;
    assert_eq!(acceptee.status, StatusCode::CREATED);

    let refusee = post_json(
        router(state.clone()),
        "/register",
        &format!(
            r#"{{"name": "Autre", "email": "autre@test.fr", "password": "{PASSWORD}", "accepted_terms_version": "v2"}}"#
        ),
        &[],
    )
    .await;
    assert_eq!(refusee.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refusee.body["error"], "terms_version_mismatch");

    db.drop().await.unwrap();
}
