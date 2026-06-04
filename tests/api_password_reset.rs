//! US-17 — Demande de réinitialisation : 202 anti-énumération, token hashé
//! en base, email envoyé avec le lien, une seule demande valable à la fois.

mod common;

use axum::http::StatusCode;
use ch_api_authenticator::routes::router;
use ch_api_authenticator::services::reset_token;
use common::*;
use std::collections::HashMap;
use std::time::Duration;

/// Attend que l'envoi détaché (tokio::spawn) ait rempli la boîte mémoire.
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

    // Anti-énumération : strictement la même réponse.
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

    // L'email part vers le bon destinataire avec le lien configuré.
    let email = wait_for_email(&outbox).await;
    assert_eq!(email.to, "martin@test.fr");
    assert!(
        email
            .body
            .contains("http://localhost:3000/reset-password?token="),
        "lien attendu dans : {}",
        email.body
    );

    // Le token du lien n'est JAMAIS stocké en clair : seul son SHA-256 l'est.
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
        .consume(&reset_token::hash(&token))
        .await
        .unwrap()
        .expect("le hash du token du lien doit exister en base");
    assert_eq!(stored.user_id, user.id.unwrap());
    assert!(!stored.used, "le token capturé était encore vierge");

    // Et le token en clair n'est pas retrouvable directement.
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

    // Deux emails partis, mais un seul token actif en base (le dernier).
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

    // Le token du premier email ne fonctionne plus, celui du second oui.
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
            .consume(&reset_token::hash(&premier))
            .await
            .unwrap()
            .is_none(),
        "le premier token doit être invalidé"
    );
    assert!(
        state
            .reset_tokens
            .consume(&reset_token::hash(&second))
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

    let response = post_json(router(state), "/password/forgot", "pas du json", &[]).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);

    db.drop().await.unwrap();
}
