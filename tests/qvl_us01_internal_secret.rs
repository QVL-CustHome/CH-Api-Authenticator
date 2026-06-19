mod common;

use axum::http::StatusCode;
use ch_api_authenticator::routes::router;
use common::*;
use std::collections::HashMap;

const INTERNAL_SECRET: &str = "un-secret-interne-de-test-suffisamment-long!";
const RESOLVE_PATH: &str = "/internal/users/resolve";

#[tokio::test]
async fn resolve_avec_bon_secret_interne_repond_200() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let user = seed_user(&state, "resolve-ok@test.fr", HashMap::new()).await;
    let id = user.id.unwrap().to_hex();

    let response = post_json(
        router(state.clone()),
        RESOLVE_PATH,
        &format!(r#"{{"ids": ["{id}"]}}"#),
        &[("x-internal-secret", INTERNAL_SECRET)],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body[0]["email"], "resolve-ok@test.fr");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn resolve_avec_jwt_secret_au_lieu_du_secret_interne_refuse_403() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = post_json(
        router(state.clone()),
        RESOLVE_PATH,
        r#"{"ids": []}"#,
        &[("x-internal-secret", JWT_SECRET)],
    )
    .await;

    assert_eq!(response.status, StatusCode::FORBIDDEN);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn resolve_avec_mauvais_secret_meme_longueur_refuse_403() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let mauvais: String = "X".repeat(INTERNAL_SECRET.len());

    let response = post_json(
        router(state.clone()),
        RESOLVE_PATH,
        r#"{"ids": []}"#,
        &[("x-internal-secret", mauvais.as_str())],
    )
    .await;

    assert_eq!(response.status, StatusCode::FORBIDDEN);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn resolve_avec_secret_vide_refuse_403() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = post_json(
        router(state.clone()),
        RESOLVE_PATH,
        r#"{"ids": []}"#,
        &[("x-internal-secret", "")],
    )
    .await;

    assert_eq!(response.status, StatusCode::FORBIDDEN);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn resolve_sans_header_secret_refuse_403() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = post_json(router(state.clone()), RESOLVE_PATH, r#"{"ids": []}"#, &[]).await;

    assert_eq!(response.status, StatusCode::FORBIDDEN);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn resolve_refuse_ne_divulgue_pas_le_secret_attendu() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = post_json(router(state.clone()), RESOLVE_PATH, r#"{"ids": []}"#, &[]).await;

    let dump = response.body.to_string();
    assert!(!dump.contains(INTERNAL_SECRET));
    assert!(!dump.contains(JWT_SECRET));

    db.drop().await.unwrap();
}
