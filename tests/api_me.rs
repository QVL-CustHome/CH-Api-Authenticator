//! US-14 — Profil : GET /me et PUT /me (email), protégés par l'auth interne (US-13).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ch_api_authenticator::routes::router;
use common::*;
use http_body_util::BodyExt;
use std::collections::HashMap;

async fn put_me(
    state: &ch_api_authenticator::state::AppState,
    token: &str,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let response = router(state.clone())
        .oneshot(
            Request::put("/me")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn get_me_renvoie_le_profil_sans_hash() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let user = seed_user(&state, "martin@test.fr", roles(&[("portail_a", "admin")])).await;
    let token = login_token(&state, "martin@test.fr").await;

    let response = get(
        router(state),
        "/me",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["user_id"], user.id.unwrap().to_hex());
    assert_eq!(response.body["email"], "martin@test.fr");
    assert_eq!(response.body["roles"]["portail_a"], "admin");
    assert_eq!(response.body["is_super_admin"], false);
    assert_eq!(response.body["whitelist_only"], false);
    assert!(response.body["created_at"].is_string());
    // Jamais de données sensibles dans le profil.
    let raw = response.body.to_string();
    assert!(
        !raw.contains("password"),
        "le profil ne doit rien exposer du mot de passe"
    );

    db.drop().await.unwrap();
}

#[tokio::test]
async fn me_sans_token_401() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let sans_token = get(router(state.clone()), "/me", &[]).await;
    assert_eq!(sans_token.status, StatusCode::UNAUTHORIZED);

    let (put_status, _) = put_me(&state, "token-bidon", r#"{"email": "x@y.fr"}"#).await;
    assert_eq!(put_status, StatusCode::UNAUTHORIZED);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn me_accessible_via_le_cookie() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = login_token(&state, "martin@test.fr").await;

    let response = get(
        router(state),
        "/me",
        &[("Cookie", &format!("ch_token={token}"))],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["email"], "martin@test.fr");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn put_me_change_l_email_et_le_login_suit() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "ancien@test.fr", HashMap::new()).await;
    let token = login_token(&state, "ancien@test.fr").await;

    let (status, body) = put_me(&state, &token, r#"{"email": "Nouveau@Test.FR"}"#).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["email"], "nouveau@test.fr",
        "email normalisé lowercase"
    );

    // L'ancien email n'existe plus, le nouveau permet de se connecter.
    assert!(
        state
            .users
            .find_by_email("ancien@test.fr")
            .await
            .unwrap()
            .is_none()
    );
    login_token(&state, "nouveau@test.fr").await;

    db.drop().await.unwrap();
}

#[tokio::test]
async fn put_me_email_deja_pris_409() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    seed_user(&state, "occupe@test.fr", HashMap::new()).await;
    let token = login_token(&state, "martin@test.fr").await;

    let (status, body) = put_me(&state, &token, r#"{"email": "occupe@test.fr"}"#).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "conflict");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn put_me_meme_email_idempotent() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = login_token(&state, "martin@test.fr").await;

    let (status, body) = put_me(&state, &token, r#"{"email": "martin@test.fr"}"#).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "martin@test.fr");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn put_me_payloads_invalides_400() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = login_token(&state, "martin@test.fr").await;

    for body in [r#"{"email": "pas-un-email"}"#, r#"{}"#, "pas du json"] {
        let (status, error) = put_me(&state, &token, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "payload : {body}");
        assert_eq!(error["error"], "bad_request");
    }

    db.drop().await.unwrap();
}
