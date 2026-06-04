//! US-19 — Refresh tokens : rotation, détection de réutilisation (révocation
//! de famille), logout, et révocation par changement/reset de mot de passe.

mod common;

use axum::http::StatusCode;
use ch_api_authenticator::routes::router;
use common::*;
use std::collections::HashMap;

const LOGIN_BODY: &str = r#"{"email": "martin@test.fr", "password": "bon-mot-de-passe"}"#;

async fn login_session(
    state: &ch_api_authenticator::state::AppState,
) -> (String, String, Vec<String>) {
    let response = post_json(router(state.clone()), "/login", LOGIN_BODY, &[]).await;
    assert_eq!(response.status, StatusCode::OK);
    (
        response.body["access_token"].as_str().unwrap().to_string(),
        response.body["refresh_token"].as_str().unwrap().to_string(),
        response.set_cookies.clone(),
    )
}

async fn refresh_with(
    state: &ch_api_authenticator::state::AppState,
    refresh_token: &str,
) -> TestResponse {
    post_json(
        router(state.clone()),
        "/refresh",
        &format!(r#"{{"refresh_token": "{refresh_token}"}}"#),
        &[],
    )
    .await
}

#[tokio::test]
async fn login_emet_un_refresh_token_et_son_cookie() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;

    let (_, refresh_token, cookies) = login_session(&state).await;

    assert_eq!(refresh_token.len(), 64, "token opaque 32 octets hex");
    let refresh_cookie = cookies
        .iter()
        .find(|c| c.starts_with("ch_refresh="))
        .expect("cookie ch_refresh posé");
    assert!(refresh_cookie.contains("HttpOnly"));
    assert!(refresh_cookie.contains(&format!("Max-Age={}", 7 * 24 * 3600)));
    assert!(cookies.iter().any(|c| c.starts_with("ch_token=")));

    db.drop().await.unwrap();
}

#[tokio::test]
async fn rotation_nominale() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", roles(&[("portail_a", "user")])).await;
    let (_, refresh1, _) = login_session(&state).await;

    let response = refresh_with(&state, &refresh1).await;
    assert_eq!(response.status, StatusCode::OK);

    // Nouveau couple : access valide (claims relus), refresh différent.
    let access = response.body["access_token"].as_str().unwrap();
    let claims = state.jwt.validate(access).unwrap();
    assert_eq!(
        claims.roles.get("portail_a").map(String::as_str),
        Some("user")
    );
    let refresh2 = response.body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(refresh1, refresh2, "le refresh token tourne à chaque usage");

    // La chaîne continue : le nouveau refresh fonctionne.
    assert_eq!(refresh_with(&state, &refresh2).await.status, StatusCode::OK);
    // L'ancien (déjà tourné) est mort — et son rejeu révoque la famille,
    // comportement détaillé dans `reutilisation_revoque_toute_la_famille`.
    assert_eq!(
        refresh_with(&state, &refresh1).await.status,
        StatusCode::UNAUTHORIZED
    );

    db.drop().await.unwrap();
}

#[tokio::test]
async fn reutilisation_revoque_toute_la_famille() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let (_, refresh1, _) = login_session(&state).await;

    // Rotation légitime → refresh2.
    let refresh2 = refresh_with(&state, &refresh1).await.body["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Un voleur rejoue refresh1 (déjà tourné) → 401 + famille révoquée.
    assert_eq!(
        refresh_with(&state, &refresh1).await.status,
        StatusCode::UNAUTHORIZED
    );

    // La victime est aussi déconnectée : refresh2 (pourtant jamais utilisé) est mort.
    assert_eq!(
        refresh_with(&state, &refresh2).await.status,
        StatusCode::UNAUTHORIZED,
        "toute la famille doit être révoquée après une réutilisation"
    );

    db.drop().await.unwrap();
}

#[tokio::test]
async fn refresh_via_le_cookie_seul() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let (_, refresh_token, _) = login_session(&state).await;

    // Pas de body : le cookie ch_refresh suffit (chemin navigateur).
    let response = post_json(
        router(state.clone()),
        "/refresh",
        "",
        &[("Cookie", &format!("ch_refresh={refresh_token}"))],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.body["access_token"].is_string());

    db.drop().await.unwrap();
}

#[tokio::test]
async fn logout_revoque_et_expire_les_cookies() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let (_, refresh_token, _) = login_session(&state).await;

    let response = post_json(
        router(state.clone()),
        "/logout",
        &format!(r#"{{"refresh_token": "{refresh_token}"}}"#),
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    // Cookies expirés (Max-Age=0) pour ch_token ET ch_refresh.
    for name in ["ch_token=", "ch_refresh="] {
        let cookie = response
            .set_cookies
            .iter()
            .find(|c| c.starts_with(name))
            .unwrap_or_else(|| panic!("cookie {name} attendu"));
        assert!(cookie.contains("Max-Age=0"), "cookie expiré : {cookie}");
    }

    // Le refresh token ne fonctionne plus.
    assert_eq!(
        refresh_with(&state, &refresh_token).await.status,
        StatusCode::UNAUTHORIZED
    );

    db.drop().await.unwrap();
}

#[tokio::test]
async fn token_inconnu_401() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let inconnu = "0".repeat(64);
    assert_eq!(
        refresh_with(&state, &inconnu).await.status,
        StatusCode::UNAUTHORIZED
    );
    // Sans token du tout.
    let sans = post_json(router(state.clone()), "/refresh", "{}", &[]).await;
    assert_eq!(sans.status, StatusCode::UNAUTHORIZED);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn changement_de_roles_pris_en_compte_a_la_rotation() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let user = seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let (access1, refresh1, _) = login_session(&state).await;

    // Aucun rôle au login.
    assert!(state.jwt.validate(&access1).unwrap().roles.is_empty());

    // Un admin attribue un rôle (mise à jour directe en attendant US-20).
    db.collection::<mongodb::bson::Document>("users")
        .update_one(
            mongodb::bson::doc! { "_id": user.id.unwrap() },
            mongodb::bson::doc! { "$set": { "roles": { "portail_a": "admin" } } },
        )
        .await
        .unwrap();

    // La rotation relit la base : le nouveau access token porte le rôle.
    let response = refresh_with(&state, &refresh1).await;
    assert_eq!(response.status, StatusCode::OK);
    let claims = state
        .jwt
        .validate(response.body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        claims.roles.get("portail_a").map(String::as_str),
        Some("admin")
    );

    db.drop().await.unwrap();
}

#[tokio::test]
async fn changement_et_reset_de_mot_de_passe_revoquent_les_refresh() {
    let db = test_db().await;
    let (state, outbox) = test_state_with_outbox(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;

    // 1. PUT /password révoque la session longue.
    let (access, refresh, _) = login_session(&state).await;
    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;
    let change = router(state.clone())
        .oneshot(
            Request::put("/password")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .body(Body::from(format!(
                    r#"{{"current_password": "{PASSWORD}", "new_password": "nouveau-mdp-solide"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(change.status(), StatusCode::OK);
    assert_eq!(
        refresh_with(&state, &refresh).await.status,
        StatusCode::UNAUTHORIZED,
        "PUT /password doit révoquer les refresh tokens"
    );

    // 2. POST /password/reset révoque aussi.
    let login2 = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "martin@test.fr", "password": "nouveau-mdp-solide"}"#,
        &[],
    )
    .await;
    let refresh2 = login2.body["refresh_token"].as_str().unwrap().to_string();

    post_json(
        router(state.clone()),
        "/password/forgot",
        r#"{"email": "martin@test.fr"}"#,
        &[],
    )
    .await;
    let email = {
        let mut found = None;
        for _ in 0..50 {
            if let Some(e) = outbox.lock().unwrap().first().cloned() {
                found = Some(e);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
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
        &format!(r#"{{"token": "{token}", "new_password": "encore-un-autre-mdp"}}"#),
        &[],
    )
    .await;
    assert_eq!(reset.status, StatusCode::OK);
    assert_eq!(
        refresh_with(&state, &refresh2).await.status,
        StatusCode::UNAUTHORIZED,
        "POST /password/reset doit révoquer les refresh tokens"
    );

    db.drop().await.unwrap();
}
