//! US-08 — Parcours de bout en bout verrouillant le contrat avec la Gateway.
//!
//! Contrairement aux suites `api_*.rs` (une route à la fois), chaque test
//! enchaîne ici le cycle complet register → login → validate via l'API
//! uniquement, comme le feraient le front et la Gateway en production.

mod common;

use axum::http::StatusCode;
use ch_api_authenticator::handlers::login::CLIENT_IP_HEADER;
use ch_api_authenticator::handlers::validate::PORTAL_HEADER;
use ch_api_authenticator::routes::router;
use common::*;
use mongodb::bson::doc;

/// Extrait la valeur du token depuis le Set-Cookie (`ch_token=<jwt>; ...`),
/// comme le fera la Gateway (US-11).
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
    // À l'inscription, la config attribue le rôle `user` sur portail_a.
    let state = test_state_with(&db, false, roles(&[("portail_a", "user")])).await;

    // 1. Inscription.
    let register = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "E2E", "email": "E2E@CustHome.FR", "password": "motdepasse-e2e"}"#,
        &[],
    )
    .await;
    assert_eq!(register.status, StatusCode::CREATED);
    let user_id = register.body["user_id"].as_str().unwrap().to_string();

    // US-8.1 : un admin valide le compte (activation directe en attendant l'endpoint, US-8.2).
    activate_user(&db, "e2e@custhome.fr").await;

    // 2. Connexion avec l'email dans une autre casse.
    let login = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "e2e@custhome.fr", "password": "motdepasse-e2e"}"#,
        &[],
    )
    .await;
    assert_eq!(login.status, StatusCode::OK);
    let access_token = login.body["access_token"].as_str().unwrap().to_string();

    // Cookie HttpOnly posé, et il porte exactement le même token.
    let cookie = login.set_cookie.expect("cookie posé au login");
    assert!(cookie.contains("HttpOnly"));
    assert_eq!(token_from_cookie(&cookie), access_token);

    // 3. Validation côté Gateway : le user_id de l'inscription est retrouvé.
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

    // 3 bis. Même validation avec le token extrait du cookie (chemin navigateur).
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

    // 4. Rôles globaux : le même rôle vaut sur n'importe quel autre portail.
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

    // Inscription, puis activation de la whitelist comme le fera un
    // super-admin au sprint 2 (mise à jour directe en attendant l'endpoint).
    let register = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "WL", "email": "wl.e2e@custhome.fr", "password": "motdepasse-e2e"}"#,
        &[],
    )
    .await;
    assert_eq!(register.status, StatusCode::CREATED);
    db.collection::<mongodb::bson::Document>("users")
        .update_one(
            doc! { "email": "wl.e2e@custhome.fr" },
            // US-8.1 : on active aussi le compte, sinon le login serait refusé.
            doc! { "$set": { "status": "active", "whitelist_only": true, "allowed_ips": ["10.1.2.3", "192.168.0.0/16"] } },
        )
        .await
        .unwrap();

    let body = r#"{"email": "wl.e2e@custhome.fr", "password": "motdepasse-e2e"}"#;

    // Login sans IP transmise → refusé.
    let sans_ip = post_json(router(state.clone()), "/login", body, &[]).await;
    assert_eq!(sans_ip.status, StatusCode::UNAUTHORIZED);

    // Login depuis une IP de la liste → token lié à cette IP.
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

    // Validation depuis la même IP → 200 avec le rôle du portail.
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

    // Le token volé et rejoué depuis une autre IP est inutilisable.
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
        r#"{"name": "Err", "email": "err.e2e@custhome.fr", "password": "motdepasse-e2e"}"#,
        &[],
    )
    .await;
    activate_user(&db, "err.e2e@custhome.fr").await;
    let token = login_token_with(&state, "err.e2e@custhome.fr", "motdepasse-e2e").await;

    // Header manquant.
    let sans_header = get(
        router(state.clone()),
        "/validate",
        &[(PORTAL_HEADER, "portail_a")],
    )
    .await;
    assert_eq!(sans_header.status, StatusCode::UNAUTHORIZED);

    // Signature falsifiée (token réel modifié).
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

    // Token expiré (forgé avec le même secret, expiration passée).
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

    // Rôles globaux : l'utilisateur a un rôle, donc /validate accorde l'accès
    // même sur un portail arbitraire (le contrôle fin est fait par l'endpoint).
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
    // default_roles vide (config par défaut) : un inscrit n'a accès à rien
    // tant qu'un super-admin ne lui a pas attribué de rôle (sprint 2).
    let state = test_state(&db).await;

    post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Neuf", "email": "neuf@custhome.fr", "password": "motdepasse-e2e"}"#,
        &[],
    )
    .await;
    activate_user(&db, "neuf@custhome.fr").await;
    let token = login_token_with(&state, "neuf@custhome.fr", "motdepasse-e2e").await;

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
