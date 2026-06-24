mod common;

use axum::http::StatusCode;
use ch_api_authenticator::domain::user::User;
use ch_api_authenticator::handlers::validate::PORTAL_HEADER;
use ch_api_authenticator::routes::router;
use ch_api_authenticator::state::AppState;
use common::*;
use mongodb::bson::oid::ObjectId;
use std::collections::HashMap;

#[tokio::test]
async fn health_ok_quand_mongo_repond() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = get(router(state), "/health", &[]).await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["status"], "ok");
    assert_eq!(response.body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(response.body["mongodb"], "ok");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn health_degraded_quand_mongo_down_mais_toujours_200() {
    let db = broken_db();
    let state = state_for_db(&db, false, HashMap::new());

    let response = get(router(state), "/health", &[]).await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "degraded ne casse pas le 200"
    );
    assert_eq!(response.body["status"], "degraded");
    assert_eq!(response.body["mongodb"], "down");
}

fn user_admin_avec_token(state: &AppState) -> (User, String) {
    let mut user = User::new(
        "stateless@test.fr",
        "$argon2id$hash".to_string(),
        vec!["admin".to_string()],
    );
    user.id = Some(ObjectId::new());
    let token = state.jwt.issue(&user, None).unwrap();
    (user, token)
}

#[tokio::test]
async fn validate_portail_valide_et_role_coherent_repond_200_quand_mongo_down() {
    let db = broken_db();
    let state = state_for_db(&db, false, HashMap::new());
    let (user, token) = user_admin_avec_token(&state);

    let response = get(
        router(state),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {token}")),
            (PORTAL_HEADER, "portail_admin"),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::OK,
        "/validate doit répondre 200 avec MongoDB down"
    );
    assert_eq!(response.body["role"], "admin");
    assert_eq!(response.body["user_id"], user.id.unwrap().to_hex());
}

#[tokio::test]
async fn validate_portail_inconnu_repond_403_quand_mongo_down() {
    let db = broken_db();
    let state = state_for_db(&db, false, HashMap::new());
    let (_user, token) = user_admin_avec_token(&state);

    let response = get(
        router(state),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {token}")),
            (PORTAL_HEADER, "portail_bugdy"),
        ],
    )
    .await;

    assert_eq!(
        response.status,
        StatusCode::FORBIDDEN,
        "/validate doit refuser un portail inconnu"
    );
}
