//! US-8.3 — Catalogue des rôles (un rôle = un nom) : CRUD et validation à l'attribution.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ch_api_authenticator::routes::router;
use common::*;
use std::collections::HashMap;

async fn delete_auth(
    state: &ch_api_authenticator::state::AppState,
    path: &str,
    token: &str,
) -> StatusCode {
    use tower::ServiceExt;
    let response = router(state.clone())
        .oneshot(
            Request::delete(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    response.status()
}

async fn put_auth(
    state: &ch_api_authenticator::state::AppState,
    path: &str,
    token: &str,
    body: &str,
) -> StatusCode {
    use tower::ServiceExt;
    let response = router(state.clone())
        .oneshot(
            Request::put(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    response.status()
}

#[tokio::test]
async fn crud_complet_des_roles() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@test.fr").await;
    let token = login_token(&state, "root@test.fr").await;
    let auth = format!("Bearer {token}");

    let create = post_json(
        router(state.clone()),
        "/roles",
        r#"{"name": "editor"}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(create.status, StatusCode::CREATED);
    assert_eq!(create.body["name"], "editor");
    let role_id = create.body["id"].as_str().unwrap().to_string();

    let list = get(router(state.clone()), "/roles", &[("Authorization", &auth)]).await;
    assert_eq!(list.status, StatusCode::OK);
    let names: Vec<&str> = list
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"editor"));

    let suppr = delete_auth(&state, &format!("/roles/{role_id}"), &token).await;
    assert_eq!(suppr, StatusCode::NO_CONTENT);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn role_duplique_409_et_nom_vide_400() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@test.fr").await;
    let token = login_token(&state, "root@test.fr").await;
    let auth = format!("Bearer {token}");

    let first = post_json(
        router(state.clone()),
        "/roles",
        r#"{"name": "editor"}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(first.status, StatusCode::CREATED);

    let dup = post_json(
        router(state.clone()),
        "/roles",
        r#"{"name": "editor"}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(dup.status, StatusCode::CONFLICT);

    let vide = post_json(
        router(state),
        "/roles",
        r#"{"name": "  "}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(vide.status, StatusCode::BAD_REQUEST);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn acces_reserve_aux_admins() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "simple@test.fr", HashMap::new()).await;
    let token = login_token(&state, "simple@test.fr").await;
    let auth = format!("Bearer {token}");

    let create = post_json(
        router(state.clone()),
        "/roles",
        r#"{"name": "r"}"#,
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(create.status, StatusCode::FORBIDDEN);
    let list = get(router(state.clone()), "/roles", &[("Authorization", &auth)]).await;
    assert_eq!(list.status, StatusCode::FORBIDDEN);

    let anonyme = get(router(state), "/roles", &[]).await;
    assert_eq!(anonyme.status, StatusCode::UNAUTHORIZED);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn suppression_role_inconnu_404() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@test.fr").await;
    let token = login_token(&state, "root@test.fr").await;

    for id in ["aaaaaaaaaaaaaaaaaaaaaaaa", "pas-un-id"] {
        let status = delete_auth(&state, &format!("/roles/{id}"), &token).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "id : {id}");
    }

    db.drop().await.unwrap();
}

#[tokio::test]
async fn attribution_refusee_si_role_absent_du_catalogue() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "cible@test.fr", HashMap::new()).await;
    let token = login_token(&state, "root@test.fr").await;
    let auth = format!("Bearer {token}");
    let target = user.id.unwrap().to_hex();
    let body = r#"{"roles": ["fantome"]}"#;

    // Rôle absent du catalogue → 400.
    let absent = put_auth(&state, &format!("/users/{target}/roles"), &token, body).await;
    assert_eq!(absent, StatusCode::BAD_REQUEST);

    // Après création du nom dans le catalogue, l'attribution est acceptée.
    post_json(
        router(state.clone()),
        "/roles",
        r#"{"name": "fantome"}"#,
        &[("Authorization", &auth)],
    )
    .await;
    let ok = put_auth(&state, &format!("/users/{target}/roles"), &token, body).await;
    assert_eq!(ok, StatusCode::OK);

    db.drop().await.unwrap();
}
