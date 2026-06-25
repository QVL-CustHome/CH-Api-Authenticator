mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ch_api_authenticator::services::client_ip::CLIENT_IP_HEADER;
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

#[tokio::test]
async fn acces_refuse_aux_non_admins() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let user = seed_user(&state, "simple@test.fr", HashMap::new()).await;
    let token = login_token(&state, "simple@test.fr").await;
    let target = user.id.unwrap().to_hex();

    let auth = format!("Bearer {token}");
    let list = get(router(state.clone()), "/users", &[("Authorization", &auth)]).await;
    assert_eq!(list.status, StatusCode::FORBIDDEN);

    let (roles_status, _) = put_json(
        &state,
        &format!("/users/{target}/roles"),
        &token,
        r#"{"roles": ["admin"]}"#,
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

    let anonyme = get(router(state), "/users", &[]).await;
    assert_eq!(anonyme.status, StatusCode::UNAUTHORIZED);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn liste_paginee_sans_hash_avec_filtre_email() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@test.fr").await;
    for i in 1..=3 {
        seed_user(&state, &format!("user{i}@test.fr"), HashMap::new()).await;
    }
    let token = login_token(&state, "root@test.fr").await;
    let auth = format!("Bearer {token}");

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

    let page3 = get(
        router(state.clone()),
        "/users?page=3&limit=2",
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(page3.body["users"].as_array().unwrap().len(), 0);

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
    seed_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let admin_token = login_token(&state, "root@test.fr").await;
    let target = user.id.unwrap().to_hex();

    seed_role(&state, "user").await;
    seed_role(&state, "admin").await;

    let avant = login_token(&state, "martin@test.fr").await;
    let refus = get(
        router(state.clone()),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {avant}")),
            (PORTAL_HEADER, "portail_admin"),
        ],
    )
    .await;
    assert_eq!(refus.status, StatusCode::FORBIDDEN);

    let (status, body) = put_json(
        &state,
        &format!("/users/{target}/roles"),
        &admin_token,
        r#"{"roles": ["user", "admin"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["roles"][0], "user");

    let apres = login_token(&state, "martin@test.fr").await;
    let acces = get(
        router(state.clone()),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {apres}")),
            (PORTAL_HEADER, "portail_admin"),
        ],
    )
    .await;
    assert_eq!(acces.status, StatusCode::OK);
    assert_eq!(acces.body["role"], "user,admin");

    put_json(
        &state,
        &format!("/users/{target}/roles"),
        &admin_token,
        r#"{"roles": []}"#,
    )
    .await;
    let retire = login_token(&state, "martin@test.fr").await;
    let refus2 = get(
        router(state),
        "/validate",
        &[
            ("Authorization", &format!("Bearer {retire}")),
            (PORTAL_HEADER, "portail_admin"),
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
    seed_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = login_token(&state, "root@test.fr").await;
    let target = user.id.unwrap().to_hex();
    seed_role(&state, "user").await;

    for body in [r#"{"roles": [""]}"#, r#"{"roles": ["  "]}"#] {
        let (status, _) = put_json(&state, &format!("/users/{target}/roles"), &token, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body : {body}");
    }

    for id in ["aaaaaaaaaaaaaaaaaaaaaaaa", "pas-un-id"] {
        let (status, _) = put_json(
            &state,
            &format!("/users/{id}/roles"),
            &token,
            r#"{"roles": ["user"]}"#,
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
    seed_admin(&state, "root@test.fr").await;
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

    let login_body = r#"{"email": "martin@test.fr", "password": "Bon-Mot-De-Passe1"}"#;
    let sans_ip = post_json(router(state.clone()), "/login", login_body, &[]).await;
    assert_eq!(sans_ip.status, StatusCode::FORBIDDEN);
    assert_eq!(sans_ip.body["error"], "device_not_allowed");

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
    seed_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = login_token(&state, "root@test.fr").await;
    let target = user.id.unwrap().to_hex();

    for body in [
        r#"{"whitelist_only": true, "allowed_ips": ["pas-une-ip"]}"#,
        r#"{"whitelist_only": true, "allowed_ips": ["999.999.0.0/8"]}"#,

        r#"{"whitelist_only": true, "allowed_ips": []}"#,
    ] {
        let (status, _) =
            put_json(&state, &format!("/users/{target}/whitelist"), &token, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body : {body}");
    }

    db.drop().await.unwrap();
}

#[tokio::test]
async fn portal_admin_non_super_a_acces() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(
        &state,
        "padmin@test.fr",
        roles(&[("portail_admin", "admin")]),
    )
    .await;
    let token = login_token(&state, "padmin@test.fr").await;

    let list = get(
        router(state),
        "/users",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn activation_desactivation_via_status_pilote_le_login() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@test.fr").await;
    let admin = login_token(&state, "root@test.fr").await;

    let register = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Pending", "email": "pending@test.fr", "password": "Bon-Mot-De-Passe1"}"#,
        &[],
    )
    .await;
    let target = register.body["user_id"].as_str().unwrap().to_string();
    let login_body = r#"{"email": "pending@test.fr", "password": "Bon-Mot-De-Passe1"}"#;

    let avant = post_json(router(state.clone()), "/login", login_body, &[]).await;
    assert_eq!(avant.status, StatusCode::FORBIDDEN);
    assert_eq!(avant.body["error"], "account_pending");

    let (status, body) = put_json(
        &state,
        &format!("/users/{target}/status"),
        &admin,
        r#"{"status": "active"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "active");

    let ok = post_json(router(state.clone()), "/login", login_body, &[]).await;
    assert_eq!(ok.status, StatusCode::OK);

    let (status, _) = put_json(
        &state,
        &format!("/users/{target}/status"),
        &admin,
        r#"{"status": "disabled"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let apres = post_json(router(state), "/login", login_body, &[]).await;
    assert_eq!(apres.status, StatusCode::FORBIDDEN);
    assert_eq!(apres.body["error"], "account_disabled");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn liste_des_comptes_en_attente() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@test.fr").await;
    seed_user(&state, "actif@test.fr", HashMap::new()).await;
    let admin = login_token(&state, "root@test.fr").await;

    for email in ["p1@test.fr", "p2@test.fr"] {
        post_json(
            router(state.clone()),
            "/register",
            &format!(r#"{{"name": "Test", "email": "{email}", "password": "Bon-Mot-De-Passe1"}}"#),
            &[],
        )
        .await;
    }

    let pending = get(
        router(state),
        "/users/pending",
        &[("Authorization", &format!("Bearer {admin}"))],
    )
    .await;
    assert_eq!(pending.status, StatusCode::OK);
    assert_eq!(pending.body["total"], 2);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn get_un_compte_et_404() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "cible@test.fr", HashMap::new()).await;
    let admin = login_token(&state, "root@test.fr").await;
    let auth = format!("Bearer {admin}");
    let target = user.id.unwrap().to_hex();

    let found = get(
        router(state.clone()),
        &format!("/users/{target}"),
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(found.status, StatusCode::OK);
    assert_eq!(found.body["email"], "cible@test.fr");
    assert_eq!(found.body["status"], "active");

    let inconnu = get(
        router(state),
        "/users/aaaaaaaaaaaaaaaaaaaaaaaa",
        &[("Authorization", &auth)],
    )
    .await;
    assert_eq!(inconnu.status, StatusCode::NOT_FOUND);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn modification_email_par_admin_et_conflit() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "avant@test.fr", HashMap::new()).await;
    seed_user(&state, "occupe@test.fr", HashMap::new()).await;
    let admin = login_token(&state, "root@test.fr").await;
    let target = user.id.unwrap().to_hex();

    let (status, body) = put_json(
        &state,
        &format!("/users/{target}"),
        &admin,
        r#"{"name": "Apres", "email": "Apres@Test.FR"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "apres@test.fr");

    let (conflit, _) = put_json(
        &state,
        &format!("/users/{target}"),
        &admin,
        r#"{"name": "Occupe", "email": "occupe@test.fr"}"#,
    )
    .await;
    assert_eq!(conflit, StatusCode::CONFLICT);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn suppression_compte_empeche_le_login() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "asupprimer@test.fr", HashMap::new()).await;
    let admin = login_token(&state, "root@test.fr").await;
    let target = user.id.unwrap().to_hex();

    let suppr = delete_auth(&state, &format!("/users/{target}"), &admin).await;
    assert_eq!(suppr, StatusCode::NO_CONTENT);

    let login = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "asupprimer@test.fr", "password": "Bon-Mot-De-Passe1"}"#,
        &[],
    )
    .await;
    assert_eq!(login.status, StatusCode::UNAUTHORIZED);

    let encore = delete_auth(&state, &format!("/users/{target}"), &admin).await;
    assert_eq!(encore, StatusCode::NOT_FOUND);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn reinitialisation_mot_de_passe_par_admin() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "user@test.fr", HashMap::new()).await;
    let admin = login_token(&state, "root@test.fr").await;
    let target = user.id.unwrap().to_hex();

    let (court, _) = put_json(
        &state,
        &format!("/users/{target}/password"),
        &admin,
        r#"{"password": "court"}"#,
    )
    .await;
    assert_eq!(court, StatusCode::BAD_REQUEST);

    let (ok, _) = put_json(
        &state,
        &format!("/users/{target}/password"),
        &admin,
        r#"{"password": "Nouveau-Mot-De-Passe1"}"#,
    )
    .await;
    assert_eq!(ok, StatusCode::NO_CONTENT);

    let ancien = post_json(
        router(state.clone()),
        "/login",
        r#"{"email": "user@test.fr", "password": "Bon-Mot-De-Passe1"}"#,
        &[],
    )
    .await;
    assert_eq!(ancien.status, StatusCode::UNAUTHORIZED);

    let nouveau = post_json(
        router(state),
        "/login",
        r#"{"email": "user@test.fr", "password": "Nouveau-Mot-De-Passe1"}"#,
        &[],
    )
    .await;
    assert_eq!(nouveau.status, StatusCode::OK);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn status_invalide_400_et_cible_inconnue_404() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_admin(&state, "root@test.fr").await;
    let user = seed_user(&state, "cible@test.fr", HashMap::new()).await;
    let admin = login_token(&state, "root@test.fr").await;
    let target = user.id.unwrap().to_hex();

    let (mauvais, _) = put_json(
        &state,
        &format!("/users/{target}/status"),
        &admin,
        r#"{"status": "n_importe_quoi"}"#,
    )
    .await;
    assert_eq!(mauvais, StatusCode::BAD_REQUEST);

    let (inconnu, _) = put_json(
        &state,
        "/users/aaaaaaaaaaaaaaaaaaaaaaaa/status",
        &admin,
        r#"{"status": "active"}"#,
    )
    .await;
    assert_eq!(inconnu, StatusCode::NOT_FOUND);

    db.drop().await.unwrap();
}
