mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ch_api_authenticator::handlers::login::CLIENT_IP_HEADER;
use ch_api_authenticator::handlers::validate::PORTAL_HEADER;
use ch_api_authenticator::routes::router;
use common::*;
use std::time::Duration;

type State = ch_api_authenticator::state::AppState;

async fn put_json_auth(
    state: &State,
    path: &str,
    token: &str,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    use http_body_util::BodyExt;
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
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn validate_status(state: &State, token: &str, portal: &str) -> StatusCode {
    get(
        router(state.clone()),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {token}")),
            (PORTAL_HEADER, portal),
        ],
    )
    .await
    .status
}

#[tokio::test]
async fn cycle_de_vie_complet_d_un_compte() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@custhome.fr").await;
    let admin = login_token(&state, "root@custhome.fr").await;

    let register = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Vie", "email": "vie@custhome.fr", "password": "Premier-Mdp-Solide1"}"#,
        &[],
    )
    .await;
    assert_eq!(register.status, StatusCode::CREATED);
    let user_id = register.body["user_id"].as_str().unwrap().to_string();

    activate_user(&db, "vie@custhome.fr").await;

    seed_role(&state, "user").await;

    let (status, _) = put_json_auth(
        &state,
        &format!("/users/{user_id}/roles"),
        &admin,
        r#"{"roles": ["user"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let login = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "vie@custhome.fr", "password": "Premier-Mdp-Solide1"}"#,
        &[],
    )
    .await;
    assert_eq!(login.status, StatusCode::OK);
    let access = login.body["access_token"].as_str().unwrap().to_string();
    let refresh = login.body["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(
        validate_status(&state, &access, "portail_a").await,
        StatusCode::OK
    );

    let me = get(
        router(state.clone()),
        "/me",
        &[("Authorization", &format!("Bearer {access}"))],
    )
    .await;
    assert_eq!(me.body["roles"][0], "user");

    let rotated = post_json(
        router(state.clone()),
        "/refresh",
        &format!(r#"{{"refresh_token": "{refresh}"}}"#),
        &[],
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK);
    let access2 = rotated.body["access_token"].as_str().unwrap().to_string();
    let refresh2 = rotated.body["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(
        validate_status(&state, &access2, "portail_a").await,
        StatusCode::OK
    );

    let (status, _) = put_json_auth(
        &state,
        "/password",
        &access2,
        r#"{"current_password": "Premier-Mdp-Solide1", "new_password": "Second-Mdp-Solide1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let dead = post_json(
        router(state.clone()),
        "/refresh",
        &format!(r#"{{"refresh_token": "{refresh2}"}}"#),
        &[],
    )
    .await;
    assert_eq!(dead.status, StatusCode::UNAUTHORIZED);

    let relogin = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "vie@custhome.fr", "password": "Second-Mdp-Solide1"}"#,
        &[],
    )
    .await;
    assert_eq!(relogin.status, StatusCode::OK);
    let refresh3 = relogin.body["refresh_token"].as_str().unwrap().to_string();

    let logout = post_json(
        router(state.clone()),
        "/logout",
        &format!(r#"{{"refresh_token": "{refresh3}"}}"#),
        &[],
    )
    .await;
    assert_eq!(logout.status, StatusCode::OK);
    let after_logout = post_json(
        router(state),
        "/refresh",
        &format!(r#"{{"refresh_token": "{refresh3}"}}"#),
        &[],
    )
    .await;
    assert_eq!(after_logout.status, StatusCode::UNAUTHORIZED);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn parcours_reset_integral() {
    let db = test_db().await;
    let (state, outbox) = test_state_with_outbox(&db).await;

    post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Oubli", "email": "oubli@custhome.fr", "password": "Mdp-Oublie-Bientot1"}"#,
        &[],
    )
    .await;
    activate_user(&db, "oubli@custhome.fr").await;

    let login = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "oubli@custhome.fr", "password": "Mdp-Oublie-Bientot1"}"#,
        &[],
    )
    .await;
    let old_refresh = login.body["refresh_token"].as_str().unwrap().to_string();

    let forgot = post_json(
        router(state.clone()),
        "/password/forgot",
        r#"{"email": "oubli@custhome.fr"}"#,
        &[],
    )
    .await;
    assert_eq!(forgot.status, StatusCode::ACCEPTED);
    let email = {
        let mut found = None;
        for _ in 0..50 {
            if let Some(e) = outbox.lock().unwrap().first().cloned() {
                found = Some(e);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        found.expect("email de reset capturé")
    };
    let token = email
        .body
        .split("token=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();

    let reset = post_json(
        router(state.clone()),
        "/password/reset",
        &format!(r#"{{"token": "{token}", "new_password": "Mdp-Tout-Neuf1"}}"#),
        &[],
    )
    .await;
    assert_eq!(reset.status, StatusCode::OK);

    login_token_with(&state, "oubli@custhome.fr", "Mdp-Tout-Neuf1").await;
    let ancien = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "oubli@custhome.fr", "password": "Mdp-Oublie-Bientot1"}"#,
        &[],
    )
    .await;
    assert_eq!(ancien.status, StatusCode::UNAUTHORIZED);

    let dead = post_json(
        router(state),
        "/refresh",
        &format!(r#"{{"refresh_token": "{old_refresh}"}}"#),
        &[],
    )
    .await;
    assert_eq!(
        dead.status,
        StatusCode::UNAUTHORIZED,
        "les sessions ouvertes avant le reset doivent tomber"
    );

    db.drop().await.unwrap();
}

#[tokio::test]
async fn whitelist_administree_de_bout_en_bout() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@custhome.fr").await;
    let admin = login_token(&state, "root@custhome.fr").await;

    let register = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Fixe", "email": "fixe@custhome.fr", "password": "Mdp-Poste-Fixe1!"}"#,
        &[],
    )
    .await;
    let user_id = register.body["user_id"].as_str().unwrap().to_string();
    activate_user(&db, "fixe@custhome.fr").await;
    seed_role(&state, "user").await;

    put_json_auth(
        &state,
        &format!("/users/{user_id}/roles"),
        &admin,
        r#"{"roles": ["user"]}"#,
    )
    .await;
    let (status, _) = put_json_auth(
        &state,
        &format!("/users/{user_id}/whitelist"),
        &admin,
        r#"{"whitelist_only": true, "allowed_ips": ["10.1.2.3"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let login_body = r#"{"email": "fixe@custhome.fr", "password": "Mdp-Poste-Fixe1!"}"#;

    let hors = post_json(router(state.clone()), "/login", login_body, &[]).await;
    assert_eq!(hors.status, StatusCode::FORBIDDEN);
    assert_eq!(hors.body["error"], "device_not_allowed");
    let login = post_json(
        router(state.clone()),
        "/login",
        login_body,
        &[(CLIENT_IP_HEADER, "10.1.2.3")],
    )
    .await;
    assert_eq!(login.status, StatusCode::OK);
    let access = login.body["access_token"].as_str().unwrap().to_string();
    let refresh = login.body["refresh_token"].as_str().unwrap().to_string();

    let ok = get(
        router(state.clone()),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {access}")),
            (PORTAL_HEADER, "portail_a"),
            (CLIENT_IP_HEADER, "10.1.2.3"),
        ],
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);
    let vol = get(
        router(state.clone()),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {access}")),
            (PORTAL_HEADER, "portail_a"),
            (CLIENT_IP_HEADER, "203.0.113.9"),
        ],
    )
    .await;
    assert_eq!(vol.status, StatusCode::UNAUTHORIZED);

    let refus = post_json(
        router(state.clone()),
        "/refresh",
        &format!(r#"{{"refresh_token": "{refresh}"}}"#),
        &[],
    )
    .await;
    assert_eq!(
        refus.status,
        StatusCode::UNAUTHORIZED,
        "rotation sans IP whitelistée refusée"
    );

    db.drop().await.unwrap();
}
