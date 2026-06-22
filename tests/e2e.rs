mod common;

use axum::http::StatusCode;
use ch_api_authenticator::services::client_ip::CLIENT_IP_HEADER;
use ch_api_authenticator::handlers::validate::PORTAL_HEADER;
use ch_api_authenticator::routes::router;
use common::*;
use mongodb::bson::doc;

fn token_from_cookie(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("ch_token=")
        .expect("cookie ch_token")
        .to_string()
}

#[tokio::test]
async fn parcours_nominal_register_login_validate_multi_portail() {
    let db = test_db().await;

    let state = test_state_with(&db, false, roles(&[("portail_a", "user")])).await;

    let register = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "E2E", "email": "E2E@CustHome.FR", "password": "Motdepasse-E2e1"}"#,
        &[],
    )
    .await;
    assert_eq!(register.status, StatusCode::CREATED);
    let user_id = register.body["user_id"].as_str().unwrap().to_string();

    activate_user(&db, "e2e@custhome.fr").await;

    let login = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "e2e@custhome.fr", "password": "Motdepasse-E2e1"}"#,
        &[],
    )
    .await;
    assert_eq!(login.status, StatusCode::OK);
    let access_token = login.body["access_token"].as_str().unwrap().to_string();

    let cookie = login.set_cookie.expect("cookie posé au login");
    assert!(cookie.contains("HttpOnly"));
    assert_eq!(token_from_cookie(&cookie), access_token);

    let validate = get(
        router(state.clone()),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {access_token}")),
            (PORTAL_HEADER, "portail_a"),
        ],
    )
    .await;
    assert_eq!(validate.status, StatusCode::OK);
    assert_eq!(validate.body["user_id"], user_id.as_str());
    assert_eq!(validate.body["role"], "user");

    let via_cookie = get(
        router(state.clone()),
        "/validate",
        &[
            (
                "Authorization",
                &format!("Bearer {}", token_from_cookie(&cookie)),
            ),
            (PORTAL_HEADER, "portail_a"),
        ],
    )
    .await;
    assert_eq!(via_cookie.status, StatusCode::OK);

    let autre_portail = get(
        router(state),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {access_token}")),
            (PORTAL_HEADER, "portail_b"),
        ],
    )
    .await;
    assert_eq!(autre_portail.status, StatusCode::OK);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn parcours_whitelist_de_bout_en_bout() {
    let db = test_db().await;
    let state = test_state_with(&db, false, roles(&[("portail_a", "user")])).await;

    let register = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "WL", "email": "wl.e2e@custhome.fr", "password": "Motdepasse-E2e1"}"#,
        &[],
    )
    .await;
    assert_eq!(register.status, StatusCode::CREATED);
    db.collection::<mongodb::bson::Document>("users")
        .update_one(
            doc! { "email": "wl.e2e@custhome.fr" },

            doc! { "$set": { "status": "active", "whitelist_only": true, "allowed_ips": ["10.1.2.3", "192.168.0.0/16"] } },
        )
        .await
        .unwrap();

    let body = r#"{"email": "wl.e2e@custhome.fr", "password": "Motdepasse-E2e1"}"#;

    let sans_ip = post_json(router(state.clone()), "/login", body, &[]).await;
    assert_eq!(sans_ip.status, StatusCode::FORBIDDEN);
    assert_eq!(sans_ip.body["error"], "device_not_allowed");

    let login = post_json(
        router(state.clone()),
        "/login",
        body,
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
            (PORTAL_HEADER, "portail_a"),
            (CLIENT_IP_HEADER, "10.1.2.3"),
        ],
    )
    .await;
    assert_eq!(meme_ip.status, StatusCode::OK);
    assert_eq!(meme_ip.body["role"], "user");

    let autre_ip = get(
        router(state),
        "/validate",
        &[
            ("Authorization", &auth),
            (PORTAL_HEADER, "portail_a"),
            (CLIENT_IP_HEADER, "203.0.113.9"),
        ],
    )
    .await;
    assert_eq!(autre_ip.status, StatusCode::UNAUTHORIZED);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn cascade_des_cas_d_erreur_sur_un_vrai_compte() {
    let db = test_db().await;
    let state = test_state_with(&db, false, roles(&[("portail_a", "user")])).await;

    post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Err", "email": "err.e2e@custhome.fr", "password": "Motdepasse-E2e1"}"#,
        &[],
    )
    .await;
    activate_user(&db, "err.e2e@custhome.fr").await;
    let token = login_token_with(&state, "err.e2e@custhome.fr", "Motdepasse-E2e1").await;

    let sans_header = get(
        router(state.clone()),
        "/validate",
        &[(PORTAL_HEADER, "portail_a")],
    )
    .await;
    assert_eq!(sans_header.status, StatusCode::UNAUTHORIZED);

    let falsifie = format!("{}AAAA", &token[..token.len() - 4]);
    let signature = get(
        router(state.clone()),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {falsifie}")),
            (PORTAL_HEADER, "portail_a"),
        ],
    )
    .await;
    assert_eq!(signature.status, StatusCode::UNAUTHORIZED);

    let expire = {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "sub": "000000000000000000000000",
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
    let token_expire = get(
        router(state.clone()),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {expire}")),
            (PORTAL_HEADER, "portail_a"),
        ],
    )
    .await;
    assert_eq!(token_expire.status, StatusCode::UNAUTHORIZED);

    let avec_role = get(
        router(state),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {token}")),
            (PORTAL_HEADER, "portail_inexistant"),
        ],
    )
    .await;
    assert_eq!(avec_role.status, StatusCode::OK);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn compte_neuf_sans_roles_refuse_sur_tous_les_portails() {
    let db = test_db().await;

    let state = test_state(&db).await;

    post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Neuf", "email": "neuf@custhome.fr", "password": "Motdepasse-E2e1"}"#,
        &[],
    )
    .await;
    activate_user(&db, "neuf@custhome.fr").await;
    let token = login_token_with(&state, "neuf@custhome.fr", "Motdepasse-E2e1").await;

    for portal in ["portail_a", "portail_b"] {
        let response = get(
            router(state.clone()),
            "/validate",
            &[
                ("Authorization", &format!("Bearer {token}")),
                (PORTAL_HEADER, portal),
            ],
        )
        .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "portail : {portal}");
    }

    db.drop().await.unwrap();
}
