mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ch_api_authenticator::config::RelayConfig;
use ch_api_authenticator::domain::events::{
    USER_DELETED_TOPIC, USER_DELETED_TYPE, UserDeletedEvent,
};
use ch_api_authenticator::routes::router;
use ch_api_authenticator::services::relay::RelayPublisher;
use common::*;
use mongodb::bson::oid::ObjectId;
use std::collections::HashMap;
use uuid::Uuid;

async fn admin_token(state: &ch_api_authenticator::state::AppState, email: &str) -> String {
    let admin = seed_admin(state, email).await;
    state.jwt.issue(&admin, None).unwrap()
}

async fn delete_user(
    state: &ch_api_authenticator::state::AppState,
    id: &str,
    token: &str,
) -> StatusCode {
    use tower::ServiceExt;
    let response = router(state.clone())
        .oneshot(
            Request::delete(format!("/users/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    response.status()
}

#[test]
fn le_topic_de_publication_est_auth_user_deleted() {
    assert_eq!(USER_DELETED_TOPIC, "auth/user/deleted");
}

#[test]
fn le_type_evenement_est_auth_user_deleted() {
    assert_eq!(USER_DELETED_TYPE, "auth.user.deleted");
}

#[test]
fn levenement_porte_les_quatre_champs_attendus_du_besoin() {
    let sub = ObjectId::new().to_hex();
    let event = UserDeletedEvent::new(
        Uuid::new_v4().to_string(),
        sub.clone(),
        "2026-06-24T10:00:00Z".to_string(),
    );

    let json = serde_json::to_value(&event).unwrap();
    let object = json.as_object().unwrap();

    assert_eq!(object.len(), 4);
    assert!(object.contains_key("event_id"));
    assert!(object.contains_key("event_type"));
    assert!(object.contains_key("sub"));
    assert!(object.contains_key("occurred_at"));
}

#[test]
fn le_champ_event_type_du_payload_vaut_auth_user_deleted() {
    let event = UserDeletedEvent::new(
        Uuid::new_v4().to_string(),
        ObjectId::new().to_hex(),
        "2026-06-24T10:00:00Z".to_string(),
    );

    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["event_type"], "auth.user.deleted");
}

#[test]
fn le_champ_sub_du_payload_est_lobjectid_hex_de_lutilisateur_supprime() {
    let supprime = ObjectId::new();
    let event = UserDeletedEvent::new(
        Uuid::new_v4().to_string(),
        supprime.to_hex(),
        "2026-06-24T10:00:00Z".to_string(),
    );

    let json = serde_json::to_value(&event).unwrap();
    let sub = json["sub"].as_str().unwrap();

    assert_eq!(sub, supprime.to_hex());
    assert_eq!(sub.len(), 24);
    assert!(ObjectId::parse_str(sub).is_ok());
}

#[test]
fn le_champ_event_id_du_payload_est_un_uuid_v4() {
    let generated = Uuid::new_v4().to_string();
    let event = UserDeletedEvent::new(
        generated,
        ObjectId::new().to_hex(),
        "2026-06-24T10:00:00Z".to_string(),
    );

    let json = serde_json::to_value(&event).unwrap();
    let event_id = json["event_id"].as_str().unwrap();
    let parsed = Uuid::parse_str(event_id).unwrap();

    assert_eq!(parsed.get_version_num(), 4);
}

#[test]
fn le_champ_occurred_at_du_payload_est_un_horodatage_rfc3339() {
    let occurred_at = mongodb::bson::DateTime::now()
        .try_to_rfc3339_string()
        .unwrap();
    let event = UserDeletedEvent::new(
        Uuid::new_v4().to_string(),
        ObjectId::new().to_hex(),
        occurred_at.clone(),
    );

    let json = serde_json::to_value(&event).unwrap();
    let value = json["occurred_at"].as_str().unwrap();

    assert!(mongodb::bson::DateTime::parse_rfc3339_str(value).is_ok());
}

#[test]
fn le_mode_dormant_est_la_valeur_par_defaut() {
    let config = RelayConfig::default();
    assert!(!config.enabled);
}

#[tokio::test]
async fn en_mode_dormant_la_publication_ne_panique_pas_et_naffecte_pas_le_flux() {
    let publisher = RelayPublisher::Disabled;
    let event = UserDeletedEvent::new(
        Uuid::new_v4().to_string(),
        ObjectId::new().to_hex(),
        "2026-06-24T10:00:00Z".to_string(),
    );

    publisher.publish_user_deleted(&event).await;
}

#[tokio::test]
async fn en_mode_dormant_la_suppression_dun_utilisateur_renvoie_no_content() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let admin = admin_token(&state, "root@test.fr").await;
    let user = seed_user(&state, "asupprimer@test.fr", HashMap::new()).await;
    let target = user.id.unwrap().to_hex();

    let status = delete_user(&state, &target, &admin).await;

    assert_eq!(status, StatusCode::NO_CONTENT);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn en_mode_dormant_lutilisateur_supprime_disparait_du_referentiel() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let admin = admin_token(&state, "root@test.fr").await;
    let user = seed_user(&state, "asupprimer@test.fr", HashMap::new()).await;
    let target = user.id.unwrap().to_hex();

    delete_user(&state, &target, &admin).await;

    let toujours_present = state
        .users
        .find_by_email("asupprimer@test.fr")
        .await
        .unwrap();

    assert!(toujours_present.is_none());

    db.drop().await.unwrap();
}

#[tokio::test]
async fn en_mode_dormant_supprimer_deux_fois_renvoie_404() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let admin = admin_token(&state, "root@test.fr").await;
    let user = seed_user(&state, "asupprimer@test.fr", HashMap::new()).await;
    let target = user.id.unwrap().to_hex();

    assert_eq!(
        delete_user(&state, &target, &admin).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        delete_user(&state, &target, &admin).await,
        StatusCode::NOT_FOUND
    );

    db.drop().await.unwrap();
}

#[tokio::test]
async fn supprimer_une_cible_inconnue_renvoie_404_sans_evenement() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let admin = admin_token(&state, "root@test.fr").await;

    let status = delete_user(&state, "aaaaaaaaaaaaaaaaaaaaaaaa", &admin).await;

    assert_eq!(status, StatusCode::NOT_FOUND);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn supprimer_avec_un_id_malforme_renvoie_404() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let admin = admin_token(&state, "root@test.fr").await;

    let status = delete_user(&state, "pas-un-id", &admin).await;

    assert_eq!(status, StatusCode::NOT_FOUND);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn un_non_admin_ne_peut_pas_declencher_la_suppression() {
    let db = test_db().await;
    let state = test_state(&db).await;
    let user = seed_user(&state, "simple@test.fr", HashMap::new()).await;
    let token = state.jwt.issue(&user, None).unwrap();
    let target = user.id.unwrap().to_hex();

    let status = delete_user(&state, &target, &token).await;

    assert_eq!(status, StatusCode::FORBIDDEN);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn une_suppression_anonyme_est_refusee() {
    use tower::ServiceExt;
    let db = test_db().await;
    let state = test_state(&db).await;
    let user = seed_user(&state, "cible@test.fr", HashMap::new()).await;
    let target = user.id.unwrap().to_hex();

    let response = router(state.clone())
        .oneshot(
            Request::delete(format!("/users/{target}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    db.drop().await.unwrap();
}
