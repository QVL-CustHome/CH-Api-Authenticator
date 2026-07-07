mod common;

use axum::http::StatusCode;
use ch_api_authenticator::routes::router;
use ch_api_authenticator::services::secure_token;
use common::*;
use std::collections::HashMap;
use std::time::Duration;

async fn wait_for_email(
    outbox: &std::sync::Arc<
        std::sync::Mutex<Vec<ch_api_authenticator::services::mailer::SentEmail>>,
    >,
) -> ch_api_authenticator::services::mailer::SentEmail {
    for _ in 0..50 {
        if let Some(email) = outbox.lock().unwrap().first().cloned() {
            return email;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("aucun email capturé après 1 s");
}

#[tokio::test]
async fn reponse_202_identique_email_connu_ou_inconnu() {
    let db = test_db().await;
    let (state, _) = test_state_with_outbox(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;

    let connu = post_json(
        router(state.clone()),
        "/password/forgot",
        r#"{"email": "martin@test.fr"}"#,
        &[],
    )
    .await;
    let inconnu = post_json(
        router(state),
        "/password/forgot",
        r#"{"email": "fantome@test.fr"}"#,
        &[],
    )
    .await;

    assert_eq!(connu.status, StatusCode::ACCEPTED);
    assert_eq!(inconnu.status, StatusCode::ACCEPTED);
    assert_eq!(connu.body, inconnu.body);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn email_envoye_avec_le_lien_et_token_hashe_en_base() {
    let db = test_db().await;
    let (state, outbox) = test_state_with_outbox(&db).await;
    let user = seed_user(&state, "martin@test.fr", HashMap::new()).await;

    let response = post_json(
        router(state.clone()),
        "/password/forgot",
        r#"{"email": "Martin@Test.FR"}"#,
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::ACCEPTED);

    let email = wait_for_email(&outbox).await;
    assert_eq!(email.to, "martin@test.fr");
    assert!(
        email
            .body
            .contains("http://localhost:3000/reset-password?token="),
        "lien attendu dans : {}",
        email.body
    );

    let token = email
        .body
        .split("token=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    assert_eq!(token.len(), 64);

    let stored = state
        .reset_tokens
        .consume(&secure_token::hash(&token))
        .await
        .unwrap()
        .expect("le hash du token du lien doit exister en base");
    assert_eq!(stored.user_id, user.id.unwrap());
    assert!(!stored.used, "le token capturé était encore vierge");

    assert!(
        state.reset_tokens.consume(&token).await.unwrap().is_none(),
        "le token en clair ne doit pas exister en base"
    );

    db.drop().await.unwrap();
}

#[tokio::test]
async fn nouvelle_demande_invalide_la_precedente() {
    let db = test_db().await;
    let (state, outbox) = test_state_with_outbox(&db).await;
    let user = seed_user(&state, "martin@test.fr", HashMap::new()).await;

    for _ in 0..2 {
        let response = post_json(
            router(state.clone()),
            "/password/forgot",
            r#"{"email": "martin@test.fr"}"#,
            &[],
        )
        .await;
        assert_eq!(response.status, StatusCode::ACCEPTED);
    }

    for _ in 0..50 {
        if outbox.lock().unwrap().len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        state
            .reset_tokens
            .count_for_user(user.id.unwrap())
            .await
            .unwrap(),
        1,
        "une nouvelle demande remplace la précédente"
    );

    let emails = outbox.lock().unwrap().clone();
    let token_of = |body: &str| {
        body.split("token=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string()
    };
    let premier = token_of(&emails[0].body);
    let second = token_of(&emails[1].body);

    assert!(
        state
            .reset_tokens
            .consume(&secure_token::hash(&premier))
            .await
            .unwrap()
            .is_none(),
        "le premier token doit être invalidé"
    );
    assert!(
        state
            .reset_tokens
            .consume(&secure_token::hash(&second))
            .await
            .unwrap()
            .is_some(),
        "le dernier token doit rester valable"
    );

    db.drop().await.unwrap();
}

#[tokio::test]
async fn email_inconnu_n_envoie_rien() {
    let db = test_db().await;
    let (state, outbox) = test_state_with_outbox(&db).await;

    let response = post_json(
        router(state),
        "/password/forgot",
        r#"{"email": "fantome@test.fr"}"#,
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::ACCEPTED);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        outbox.lock().unwrap().is_empty(),
        "aucun email pour un compte inexistant"
    );

    db.drop().await.unwrap();
}

#[tokio::test]
async fn json_malforme_400() {
    let db = test_db().await;
    let (state, _) = test_state_with_outbox(&db).await;

    for path in ["/password/forgot", "/password/reset"] {
        let response = post_json(router(state.clone()), path, "pas du json", &[]).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "route : {path}");
    }

    db.drop().await.unwrap();
}

async fn forgot_and_capture_token(
    state: &ch_api_authenticator::state::AppState,
    outbox: &std::sync::Arc<
        std::sync::Mutex<Vec<ch_api_authenticator::services::mailer::SentEmail>>,
    >,
    email: &str,
) -> String {
    outbox.lock().unwrap().clear();
    let response = post_json(
        router(state.clone()),
        "/password/forgot",
        &format!(r#"{{"email": "{email}"}}"#),
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::ACCEPTED);
    let email = wait_for_email(outbox).await;
    email
        .body
        .split("token=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn parcours_complet_forgot_reset_login() {
    let db = test_db().await;
    let (state, outbox) = test_state_with_outbox(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = forgot_and_capture_token(&state, &outbox, "martin@test.fr").await;

    let reset = post_json(
        router(state.clone()),
        "/password/reset",
        &format!(r#"{{"token": "{token}", "new_password": "Example-New-Strong-1"}}"#),
        &[],
    )
    .await;
    assert_eq!(reset.status, StatusCode::OK);

    login_token_with(&state, "martin@test.fr", "Example-New-Strong-1").await;
    let ancien = post_json(
        router(state.clone()),
        "/login",
        &format!(r#"{{"email": "martin@test.fr", "password": "{PASSWORD}"}}"#),
        &[],
    )
    .await;
    assert_eq!(ancien.status, StatusCode::UNAUTHORIZED);

    let stored = state
        .users
        .find_by_email("martin@test.fr")
        .await
        .unwrap()
        .unwrap();
    assert!(stored.password_hash.starts_with("$argon2id$"));

    db.drop().await.unwrap();
}

#[tokio::test]
async fn token_a_usage_strictement_unique() {
    let db = test_db().await;
    let (state, outbox) = test_state_with_outbox(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = forgot_and_capture_token(&state, &outbox, "martin@test.fr").await;

    let body = format!(r#"{{"token": "{token}", "new_password": "Example-New-Strong-1"}}"#);
    let premier = post_json(router(state.clone()), "/password/reset", &body, &[]).await;
    assert_eq!(premier.status, StatusCode::OK);

    let rejeu = post_json(router(state), "/password/reset", &body, &[]).await;
    assert_eq!(rejeu.status, StatusCode::BAD_REQUEST);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn token_inconnu_ou_expire_400_generique() {
    let db = test_db().await;
    let (state, _) = test_state_with_outbox(&db).await;
    let user = seed_user(&state, "martin@test.fr", HashMap::new()).await;

    let inconnu = post_json(
        router(state.clone()),
        "/password/reset",
        r#"{"token": "0000000000000000000000000000000000000000000000000000000000000000", "new_password": "Example-New-Strong-1"}"#,
        &[],
    )
    .await;
    assert_eq!(inconnu.status, StatusCode::BAD_REQUEST);

    let token = ch_api_authenticator::services::secure_token::generate();
    state
        .reset_tokens
        .replace_for_user(
            user.id.unwrap(),
            &ch_api_authenticator::services::secure_token::hash(&token),
            Duration::ZERO,
        )
        .await
        .unwrap();
    let expire = post_json(
        router(state.clone()),
        "/password/reset",
        &format!(r#"{{"token": "{token}", "new_password": "Example-New-Strong-1"}}"#),
        &[],
    )
    .await;
    assert_eq!(expire.status, StatusCode::BAD_REQUEST);

    assert_eq!(inconnu.body, expire.body);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn mot_de_passe_trop_court_ne_brule_pas_le_token() {
    let db = test_db().await;
    let (state, outbox) = test_state_with_outbox(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;
    let token = forgot_and_capture_token(&state, &outbox, "martin@test.fr").await;

    let court = post_json(
        router(state.clone()),
        "/password/reset",
        &format!(r#"{{"token": "{token}", "new_password": "court"}}"#),
        &[],
    )
    .await;
    assert_eq!(court.status, StatusCode::BAD_REQUEST);

    let retry = post_json(
        router(state),
        "/password/reset",
        &format!(r#"{{"token": "{token}", "new_password": "Example-New-Strong-1"}}"#),
        &[],
    )
    .await;
    assert_eq!(
        retry.status,
        StatusCode::OK,
        "le token ne doit pas être consommé par un essai invalide"
    );

    db.drop().await.unwrap();
}
