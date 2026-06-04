//! US-05 — Validation du token pour la Gateway : résolution du rôle par
//! portail (X-Portal), super-admin partout, claim ip revérifié, 200/401/403.

mod common;

use axum::http::StatusCode;
use ch_api_authenticator::handlers::login::CLIENT_IP_HEADER;
use ch_api_authenticator::handlers::validate::PORTAL_HEADER;
use ch_api_authenticator::routes::router;
use common::*;

const WHITELIST_BODY: &str = r#"{"email": "secure@test.fr", "password": "bon-mot-de-passe"}"#;

#[tokio::test]
async fn token_valide_200_avec_role_du_portail() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let user = seed_user(
        &state,
        "martin@test.fr",
        roles(&[("portail_a", "admin"), ("portail_b", "user")]),
    )
    .await;
    let token = login_token(&state, "martin@test.fr").await;

    // Le rôle dépend du portail visé.
    for (portal, expected_role) in [("portail_a", "admin"), ("portail_b", "user")] {
        let response = get(
            router(state.clone()),
            "/validate",
            &[
                ("Authorization", &format!("Bearer {token}")),
                (PORTAL_HEADER, portal),
            ],
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        // Contrat exact consommé par la Gateway Go (AuthResponse de auth.go).
        assert_eq!(response.body["user_id"], user.id.unwrap().to_hex());
        assert_eq!(response.body["role"], expected_role);
    }

    db.drop().await.unwrap();
}

#[tokio::test]
async fn aucun_role_sur_le_portail_403() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", roles(&[("portail_a", "user")])).await;
    let token = login_token(&state, "martin@test.fr").await;

    let response = get(
        router(state),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {token}")),
            (PORTAL_HEADER, "portail_inconnu"),
        ],
    )
    .await;

    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.body["error"], "forbidden");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn super_admin_admin_sur_tous_les_portails() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_super_admin(&state, "root@test.fr").await;
    let token = login_token(&state, "root@test.fr").await;

    // Aucun rôle explicite, mais super-admin → admin partout.
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
        assert_eq!(response.body["role"], "admin");
    }

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

    // Service jumeau avec TTL nul : le token émis est immédiatement expiré
    // (la validation jsonwebtoken applique une tolérance par défaut de 60 s,
    // donc on force un TTL "négatif" en forgeant les claims via un TTL 0 puis
    // en attendant la fin de la fenêtre serait trop lent : on forge plutôt
    // un token avec le même secret et une expiration passée).
    let expired = {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "sub": user.id.unwrap().to_hex(),
            "roles": {"portail_a": "user"},
            "super_admin": false,
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

    // Login depuis l'IP autorisée → token lié à 10.1.2.3.
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

    // Même IP → 200 ; IP différente ou absente → 401.
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
    // 403 attendu : IP OK mais aucun rôle (utilisateur whitelist sans rôles) —
    // prouve que le check IP passe AVANT la résolution du rôle.
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

    // Pas de claim ip → le header X-Client-IP n'est pas exigé ni comparé.
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

/// Reproduit le décodage strict du middleware Go de la Gateway (`auth.go`) :
/// réponse 200 = JSON avec `user_id` non vide et `role`.
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
    // auth.go : Decode(&authData) puis rejet si authData.UserID == ""
    let user_id = response.body["user_id"].as_str().unwrap_or_default();
    assert!(!user_id.is_empty(), "la Gateway rejette un user_id vide");
    assert!(response.body["role"].is_string());

    db.drop().await.unwrap();
}
