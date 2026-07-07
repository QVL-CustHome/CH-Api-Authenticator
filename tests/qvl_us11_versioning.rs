mod common;

use axum::http::StatusCode;
use ch_api_authenticator::handlers::validate::PORTAL_HEADER;
use ch_api_authenticator::routes::{API_VERSION_PREFIX, router};
use common::*;

#[tokio::test]
async fn route_publique_exposee_sous_v1() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", roles(&[("portail_a", "user")])).await;
    let token = login_token(&state, "martin@test.fr").await;

    let response = get(
        router(state),
        &format!("{API_VERSION_PREFIX}/validate"),
        &[
            ("Authorization", &format!("Bearer {token}")),
            (PORTAL_HEADER, "portail_a"),
        ],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["role"], "user");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn route_publique_legacy_sans_prefixe_toujours_disponible() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", roles(&[("portail_a", "user")])).await;
    let token = login_token(&state, "martin@test.fr").await;

    let response = get(
        router(state),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {token}")),
            (PORTAL_HEADER, "portail_a"),
        ],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn route_interne_non_versionnee() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let versionnee = post_json(
        router(state.clone()),
        &format!("{API_VERSION_PREFIX}/internal/users/resolve"),
        r#"{"ids": []}"#,
        &[],
    )
    .await;
    assert_eq!(versionnee.status, StatusCode::NOT_FOUND);

    let interne = post_json(
        router(state),
        "/internal/users/resolve",
        r#"{"ids": []}"#,
        &[(
            "x-internal-secret",
            "un-secret-interne-de-test-suffisamment-long!",
        )],
    )
    .await;
    assert_eq!(interne.status, StatusCode::OK);

    db.drop().await.unwrap();
}
