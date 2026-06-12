mod common;

use axum::http::StatusCode;
use ch_api_authenticator::routes::router;
use common::*;

#[tokio::test]
async fn ping_repond_200_avec_version() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = get(router(state), "/ping", &[]).await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["service"], "ch-api-authenticator");
    assert_eq!(response.body["version"], env!("CARGO_PKG_VERSION"));

    db.drop().await.unwrap();
}

#[tokio::test]
async fn route_inconnue_repond_404() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = get(router(state), "/inconnue", &[]).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);

    db.drop().await.unwrap();
}
