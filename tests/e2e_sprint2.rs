//! US-21 — Parcours de bout en bout du sprint 2 « Cycle de vie utilisateur ».
//!
//! Contrairement aux suites `api_*.rs`, TOUT passe ici par l'API — y compris
//! les actions d'administration (le seul seed direct est le super-admin,
//! équivalent du seed ADMIN_EMAIL/ADMIN_PASSWORD du démarrage).

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

/// Cycle de vie complet : inscription → attribution admin via API → accès
/// portail → rotation de session → changement de mdp → reconnexion → logout.
#[tokio::test]
async fn cycle_de_vie_complet_d_un_compte() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@custhome.fr").await;
    let admin = login_token(&state, "root@custhome.fr").await;

    // 1. Inscription : aucun accès.
    let register = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Vie", "email": "vie@custhome.fr", "password": "premier-mdp-solide"}"#,
        &[],
    )
    .await;
    assert_eq!(register.status, StatusCode::CREATED);
    let user_id = register.body["user_id"].as_str().unwrap().to_string();

    // US-8.1 : le compte est créé en attente ; un admin l'active (activation
    // directe en attendant l'endpoint d'administration, US-8.2).
    activate_user(&db, "vie@custhome.fr").await;
    // US-8.3 : le rôle attribué doit exister au catalogue.
    seed_role(&state, "user").await;

    // 2. Le super-admin attribue un rôle VIA L'API.
    let (status, _) = put_json_auth(
        &state,
        &format!("/users/{user_id}/roles"),
        &admin,
        r#"{"roles": ["user"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 3. Login : la session ouvre l'accès au portail.
    let login = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "vie@custhome.fr", "password": "premier-mdp-solide"}"#,
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

    // 4. /me reflète le rôle attribué.
    let me = get(
        router(state.clone()),
        "/me",
        &[("Authorization", &format!("Bearer {access}"))],
    )
    .await;
    assert_eq!(me.body["roles"][0], "user");

    // 5. Rotation : le nouveau access token donne toujours accès.
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

    // 6. Changement de mot de passe : la session longue tombe.
    let (status, _) = put_json_auth(
        &state,
        "/password",
        &access2,
        r#"{"current_password": "premier-mdp-solide", "new_password": "second-mdp-solide"}"#,
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

    // 7. Reconnexion avec le nouveau mdp, puis logout → refresh mort.
    let relogin = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "vie@custhome.fr", "password": "second-mdp-solide"}"#,
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

/// Parcours « mot de passe oublié » intégral, y compris la chute des
/// sessions ouvertes avant le reset.
#[tokio::test]
async fn parcours_reset_integral() {
    let db = test_db().await;
    let (state, outbox) = test_state_with_outbox(&db).await;

    post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Oubli", "email": "oubli@custhome.fr", "password": "mdp-oublie-bientot"}"#,
        &[],
    )
    .await;
    activate_user(&db, "oubli@custhome.fr").await;

    // Session ouverte AVANT le reset : elle devra tomber.
    let login = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "oubli@custhome.fr", "password": "mdp-oublie-bientot"}"#,
        &[],
    )
    .await;
    let old_refresh = login.body["refresh_token"].as_str().unwrap().to_string();

    // Demande de reset → lien capté dans l'email.
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

    // Reset → nouveau mdp actif, ancien refusé, session d'avant morte.
    let reset = post_json(
        router(state.clone()),
        "/password/reset",
        &format!(r#"{{"token": "{token}", "new_password": "mdp-tout-neuf"}}"#),
        &[],
    )
    .await;
    assert_eq!(reset.status, StatusCode::OK);

    login_token_with(&state, "oubli@custhome.fr", "mdp-tout-neuf").await;
    let ancien = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "oubli@custhome.fr", "password": "mdp-oublie-bientot"}"#,
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

/// Whitelist administrée via l'API et appliquée sur tout le cycle :
/// login, validate et rotation.
#[tokio::test]
async fn whitelist_administree_de_bout_en_bout() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@custhome.fr").await;
    let admin = login_token(&state, "root@custhome.fr").await;

    let register = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Fixe", "email": "fixe@custhome.fr", "password": "mdp-poste-fixe!"}"#,
        &[],
    )
    .await;
    let user_id = register.body["user_id"].as_str().unwrap().to_string();
    activate_user(&db, "fixe@custhome.fr").await;
    seed_role(&state, "user").await;

    // L'admin attribue un rôle ET active la whitelist via l'API.
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

    let login_body = r#"{"email": "fixe@custhome.fr", "password": "mdp-poste-fixe!"}"#;

    // Login refusé hors whitelist (403 dédié), accepté depuis l'IP autorisée.
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

    // /validate : OK depuis l'IP de login, refusé depuis une autre.
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

    // La rotation exige aussi une IP whitelistée.
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
