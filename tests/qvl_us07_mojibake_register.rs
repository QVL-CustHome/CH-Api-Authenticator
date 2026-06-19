mod common;

use axum::http::StatusCode;
use ch_api_authenticator::routes::router;
use common::*;
use std::collections::HashMap;

const MOJIBAKE_FRAGMENTS: [&str; 6] = ["Ã©", "Ã ", "Ã¨", "Ã¢", "Ã®", "Ã´"];

const REGISTER_SOURCE: &str = include_str!("../src/handlers/register.rs");

#[test]
fn source_register_contient_les_litteraux_utf8_corrects() {
    assert!(REGISTER_SOURCE.contains("email déjà utilisé"));
    assert!(REGISTER_SOURCE.contains("Insertion utilisateur en échec"));
}

#[test]
fn source_register_sans_aucun_mojibake() {
    for fragment in MOJIBAKE_FRAGMENTS {
        assert!(
            !REGISTER_SOURCE.contains(fragment),
            "mojibake « {fragment} » present dans register.rs"
        );
    }
}

#[tokio::test]
async fn email_deja_utilise_409_message_utf8_lisible() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "doublon@test.fr", HashMap::new()).await;

    let response = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Doublon", "email": "Doublon@Test.FR", "password": "Motdepasse1!"}"#,
        &[],
    )
    .await;

    assert_eq!(response.status, StatusCode::CONFLICT);
    let message = response.body["message"]
        .as_str()
        .expect("message present dans la reponse 409");
    assert_eq!(message, "email déjà utilisé");

    db.drop().await.unwrap();
}

#[tokio::test]
async fn message_409_sans_caracteres_parasites() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "parasite@test.fr", HashMap::new()).await;

    let response = post_json(
        router(state.clone()),
        "/register",
        r#"{"name": "Parasite", "email": "parasite@test.fr", "password": "Motdepasse1!"}"#,
        &[],
    )
    .await;

    let message = response.body["message"].as_str().unwrap();
    for fragment in MOJIBAKE_FRAGMENTS {
        assert!(
            !message.contains(fragment),
            "fragment de mojibake « {fragment} » trouve dans : {message}"
        );
    }

    db.drop().await.unwrap();
}
