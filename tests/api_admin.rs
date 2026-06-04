//! US-20 — Administration super-admin : liste paginée, attribution des
//! rôles par portail, gestion de la whitelist IP.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ch_api_authenticator::handlers::login::CLIENT_IP_HEADER;
use ch_api_authenticator::handlers::validate::PORTAL_HEADER;
use ch_api_authenticator::routes::router;
use common::*;
use std::collections::HashMap;

async fn put_json(
    state: &ch_api_authenticator::state::AppState,
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
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn acces_refuse_aux_non_admins() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let user = seed_user(&state, "simple@test.fr", HashMap::new()).await;
    let token = login_token(&state, "simple@test.fr").await;
    let target = user.id.unwrap().to_hex();

    // 403 pour un utilisateur normal, sur les trois routes.
    let auth = format!("Bearer {token}");
    let list = get(router(state.clone()), "/users", &[("Authorization", &auth)]).await;
    assert_eq!(list.status, StatusCode::FORBIDDEN);

    let (roles_status, _) = put_json(
        &state,
        &format!("/users/{target}/roles"),
        &token,
        r#"{"roles": {"portail_a": "admin"}}"#,
    )
    .await;
    assert_eq!(roles_status, StatusCode::FORBIDDEN);

    let (wl_status, _) = put_json(
        &state,
        &format!("/users/{target}/whitelist"),
        &token,
        r#"{"whitelist_only": false}"#,
    )
    .await;
    assert_eq!(wl_status, StatusCode::FORBIDDEN);

    // 401 sans token.
    let anonyme = get(router(state), "/users", &[]).await;
    assert_eq!(anonyme.status, StatusCode::UNAUTHORIZED);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn liste_paginee_sans_hash_avec_filtre_email() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_super_admin(&state, "root@test.fr").await;
    for i in 1..=3 {
        seed_user(&state, &format!("user{i}@test.fr"), HashMap::new()).await;
    }
    let token = login_token(&state, "root@test.fr").await;
    let auth = format!("Bearer {token}");

    // Page 1, limit 2 → 2 utilisateurs sur 4 au total.
    let page1 = get(
        router(state.clone()),
        "/users?page=1&limit=2",
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(page1.status, StatusCode::OK);
    assert_eq!(page1.body["total"], 4);
    assert_eq!(page1.body["users"].as_array().unwrap().len(), 2);
    assert!(
        !page1.body.to_string().contains("password"),
        "jamais de hash dans la liste"
    );

    // Page 3 (limit 2) → il ne reste personne... si : 4 users → page 2 a 2 entrées, page 3 vide.
    let page3 = get(
        router(state.clone()),
        "/users?page=3&limit=2",
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(page3.body["users"].as_array().unwrap().len(), 0);

    // Filtre email exact.
    let filtre = get(
        router(state),
        "/users?email=user2@test.fr",
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(filtre.body["total"], 1);
    assert_eq!(filtre.body["users"][0]["email"], "user2@test.fr");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn attribution_de_roles_visible_au_validate_apres_relogin() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_super_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let admin_token = login_token(&state, "root@test.fr").await;
    let target = user.id.unwrap().to_hex();

    // Avant attribution : aucun accès au portail.
    let avant = login_token(&state, "martin@test.fr").await;
    let refus = get(
        router(state.clone()),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {avant}")),
            (PORTAL_HEADER, "portail_a"),
        ],
    )
    .await;
    assert_eq!(refus.status, StatusCode::FORBIDDEN);

    // L'admin attribue le rôle.
    let (status, body) = put_json(
        &state,
        &format!("/users/{target}/roles"),
        &admin_token,
        r#"{"roles": {"portail_a": "user", "portail_b": "admin"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["roles"]["portail_a"], "user");

    // Après re-login : accès accordé avec le bon rôle.
    let apres = login_token(&state, "martin@test.fr").await;
    let acces = get(
        router(state.clone()),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {apres}")),
            (PORTAL_HEADER, "portail_a"),
        ],
    )
    .await;
    assert_eq!(acces.status, StatusCode::OK);
    assert_eq!(acces.body["role"], "user");

    // Retrait des rôles → 403 au prochain login.
    put_json(
        &state,
        &format!("/users/{target}/roles"),
        &admin_token,
        r#"{"roles": {}}"#,
    )
    .await;
    let retire = login_token(&state, "martin@test.fr").await;
    let refus2 = get(
        router(state),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {retire}")),
            (PORTAL_HEADER, "portail_a"),
        ],
    )
    .await;
    assert_eq!(refus2.status, StatusCode::FORBIDDEN);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn roles_invalides_400_et_cible_inconnue_404() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_super_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = login_token(&state, "root@test.fr").await;
    let target = user.id.unwrap().to_hex();

    // Portail ou rôle vide → 400.
    for body in [
        r#"{"roles": {"": "admin"}}"#,
        r#"{"roles": {"portail_a": "  "}}"#,
    ] {
        let (status, _) = put_json(&state, &format!("/users/{target}/roles"), &token, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body : {body}");
    }

    // Cible inconnue ou id illisible → 404.
    for id in ["aaaaaaaaaaaaaaaaaaaaaaaa", "pas-un-id"] {
        let (status, _) = put_json(
            &state,
            &format!("/users/{id}/roles"),
            &token,
            r#"{"roles": {"portail_a": "user"}}"#,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "id : {id}");
    }

    db.drop().await.unwrap();
}

#[tokio::test]
async fn whitelist_activee_par_l_admin_s_applique_au_login() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_super_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let admin_token = login_token(&state, "root@test.fr").await;
    let target = user.id.unwrap().to_hex();

    let (status, body) = put_json(
        &state,
        &format!("/users/{target}/whitelist"),
        &admin_token,
        r#"{"whitelist_only": true, "allowed_ips": ["10.1.2.3", "192.168.0.0/16"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["whitelist_only"], true);

    // Sans IP transmise → refusé ; depuis une IP autorisée → accepté.
    let login_body = r#"{"email": "martin@test.fr", "password": "bon-mot-de-passe"}"#;
    let sans_ip = post_json(router(state.clone()), "/login", login_body, &[]).await;
    assert_eq!(sans_ip.status, StatusCode::UNAUTHORIZED);

    let bonne_ip = post_json(
        router(state),
        "/login",
        login_body,
        &[(CLIENT_IP_HEADER, "10.1.2.3")],
    )
    .await;
    assert_eq!(bonne_ip.status, StatusCode::OK);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn whitelist_entrees_invalides_400() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_super_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = login_token(&state, "root@test.fr").await;
    let target = user.id.unwrap().to_hex();

    for body in [
        r#"{"whitelist_only": true, "allowed_ips": ["pas-une-ip"]}"#,
        r#"{"whitelist_only": true, "allowed_ips": ["999.999.0.0/8"]}"#,
        // whitelist_only sans aucune IP : verrouillage définitif refusé.
        r#"{"whitelist_only": true, "allowed_ips": []}"#,
    ] {
        let (status, _) =
            put_json(&state, &format!("/users/{target}/whitelist"), &token, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body : {body}");
    }

    db.drop().await.unwrap();
}
