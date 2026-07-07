mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ch_api_authenticator::routes::router;
use common::*;
use http_body_util::BodyExt;
use std::collections::HashMap;

async fn put_password(
    state: &ch_api_authenticator::state::AppState,
    token: Option<&str>,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let mut request = Request::put("/password").header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = router(state.clone())
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn changement_nominal_et_bascule_du_login() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = login_token(&state, "martin@test.fr").await;

    let (status, _) = put_password(
        &state,
        Some(&token),
        &format!(r#"{{"current_password": "{PASSWORD}", "new_password": "Example-New-Strong-1"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    login_token_with(&state, "martin@test.fr", "Example-New-Strong-1").await;
    let ancien = post_json(
        router(state.clone()),
        "/login",
        &format!(r#"{{"email": "martin@test.fr", "password": "{PASSWORD}"}}"#),
        &[],
    )
    .await;
    assert_eq!(ancien.status, StatusCode::UNAUTHORIZED);

    let stored = state
        .users
        .find_by_email("martin@test.fr")
        .await
        .unwrap()
        .unwrap();
    assert!(stored.password_hash.starts_with("$argon2id$"));

    db.drop().await.unwrap();
}

#[tokio::test]
async fn ancien_mot_de_passe_faux_401_generique() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = login_token(&state, "martin@test.fr").await;

    let (status, body) = put_password(
        &state,
        Some(&token),
        r#"{"current_password": "mauvais", "new_password": "Example-New-Strong-1"}"#,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unauthorized");

    login_token(&state, "martin@test.fr").await;

    db.drop().await.unwrap();
}

#[tokio::test]
async fn nouveau_mot_de_passe_trop_court_400_sans_changement() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = login_token(&state, "martin@test.fr").await;

    let (status, _) = put_password(
        &state,
        Some(&token),
        &format!(r#"{{"current_password": "{PASSWORD}", "new_password": "court"}}"#),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);

    login_token(&state, "martin@test.fr").await;

    db.drop().await.unwrap();
}

#[tokio::test]
async fn sans_token_401() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let (status, _) = put_password(
        &state,
        None,
        r#"{"current_password": "x", "new_password": "Example-New-Strong-1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn json_malforme_400() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = login_token(&state, "martin@test.fr").await;

    let (status, _) = put_password(&state, Some(&token), "pas du json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    db.drop().await.unwrap();
}
