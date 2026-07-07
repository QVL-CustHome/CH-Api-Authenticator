mod common;

use axum::http::StatusCode;
use ch_api_authenticator::handlers::validate::PORTAL_HEADER;
use ch_api_authenticator::routes::router;
use ch_api_authenticator::services::client_ip::CLIENT_IP_HEADER;
use common::*;
use std::collections::HashMap;

const WHITELIST_BODY: &str = r#"{"email": "secure@test.fr", "password": "Bon-Mot-De-Passe1"}"#;

#[tokio::test]
async fn token_valide_200_role_global_quel_que_soit_le_portail() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let user = seed_user(&state, "martin@test.fr", roles(&[("portail_a", "admin")])).await;
    let token = login_token(&state, "martin@test.fr").await;

    for portal in ["portail_a", "portail_b", "portail_futur"] {
        let response = get(
            router(state.clone()),
            "/validate",
            &[
                ("Authorization", &format!("Bearer {token}")),
                (PORTAL_HEADER, portal),
            ],
        )
        .await;

        assert_eq!(response.status, StatusCode::OK, "portail : {portal}");

        assert_eq!(response.body["user_id"], user.id.unwrap().to_hex());
        assert_eq!(response.body["role"], "admin");
    }

    db.drop().await.unwrap();
}

#[tokio::test]
async fn aucun_role_403() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
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

    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.body["error"], "forbidden");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn tokens_invalides_401() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", roles(&[("portail_a", "user")])).await;
    let token = login_token(&state, "martin@test.fr").await;
    let falsifie = format!("{}AAAA", &token[..token.len() - 4]);

    let cases: Vec<(&str, Vec<(&str, String)>)> = vec![
        ("header absent", vec![]),
        (
            "pas un Bearer",
            vec![("Authorization", format!("Basic {token}"))],
        ),
        (
            "Bearer vide",
            vec![("Authorization", "Bearer ".to_string())],
        ),
        (
            "token falsifié",
            vec![("Authorization", format!("Bearer {falsifie}"))],
        ),
        (
            "pas un JWT",
            vec![("Authorization", "Bearer nimporte.quoi.dutout".to_string())],
        ),
    ];

    for (label, headers) in cases {
        let mut all_headers: Vec<(&str, &str)> = vec![(PORTAL_HEADER, "portail_a")];
        all_headers.extend(headers.iter().map(|(n, v)| (*n, v.as_str())));

        let response = get(router(state.clone()), "/validate", &all_headers).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "cas : {label}");
        assert_eq!(response.body["error"], "unauthorized");
    }

    db.drop().await.unwrap();
}

#[tokio::test]
async fn token_expire_401() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let user = seed_user(&state, "martin@test.fr", roles(&[("portail_a", "user")])).await;

    let expired = {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "sub": user.id.unwrap().to_hex(),
            "roles": {"portail_a": "user"},
            "iat": now - 3600,
            "exp": now - 600,
        });
        jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
        )
        .unwrap()
    };

    let response = get(
        router(state),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {expired}")),
            (PORTAL_HEADER, "portail_a"),
        ],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn portal_manquant_400() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", roles(&[("portail_a", "user")])).await;
    let token = login_token(&state, "martin@test.fr").await;

    let response = get(
        router(state),
        "/validate",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.body["error"], "bad_request");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn token_whitelist_lie_a_l_ip_de_login() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_whitelist_user(&state, "secure@test.fr", &["10.1.2.3"]).await;

    let login = post_json(
        router(state.clone()),
        "/login",
        WHITELIST_BODY,
        &[(CLIENT_IP_HEADER, "10.1.2.3")],
    )
    .await;
    assert_eq!(login.status, StatusCode::OK);
    let token = login.body["access_token"].as_str().unwrap().to_string();
    let auth = format!("Bearer {token}");

    let meme_ip = get(
        router(state.clone()),
        "/validate",
        &[
            ("Authorization", &auth),
            (PORTAL_HEADER, "p"),
            (CLIENT_IP_HEADER, "10.1.2.3"),
        ],
    )
    .await;

    assert_eq!(meme_ip.status, StatusCode::FORBIDDEN);

    let autre_ip = get(
        router(state.clone()),
        "/validate",
        &[
            ("Authorization", &auth),
            (PORTAL_HEADER, "p"),
            (CLIENT_IP_HEADER, "8.8.8.8"),
        ],
    )
    .await;
    assert_eq!(autre_ip.status, StatusCode::UNAUTHORIZED);

    let sans_ip = get(
        router(state),
        "/validate",
        &[("Authorization", &auth), (PORTAL_HEADER, "p")],
    )
    .await;
    assert_eq!(sans_ip.status, StatusCode::UNAUTHORIZED);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn user_normal_sans_claim_ip_valide_depuis_partout() {
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
            (CLIENT_IP_HEADER, "203.0.113.50"),
        ],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn contrat_gateway_user_id_non_vide_et_role_present() {
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

    let user_id = response.body["user_id"].as_str().unwrap_or_default();
    assert!(!user_id.is_empty(), "la Gateway rejette un user_id vide");
    assert!(response.body["role"].is_string());

    db.drop().await.unwrap();
}
