mod common;

use axum::http::StatusCode;
use ch_api_authenticator::domain::user::User;
use ch_api_authenticator::handlers::validate::PORTAL_HEADER;
use ch_api_authenticator::routes::router;
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

#[tokio::test]
async fn validate_pleinement_fonctionnel_quand_mongo_down() {
    let db = broken_db();
    let state = state_for_db(&db, false, HashMap::new());

    let mut user = User::new(
        "stateless@test.fr",
        "$argon2id$hash".to_string(),
        vec!["admin".to_string()],
    );
    user.id = Some(ObjectId::new());
    let token = state.jwt.issue(&user, None).unwrap();

    let response = get(
        router(state),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {token}")),
            (PORTAL_HEADER, "portail_a"),
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
