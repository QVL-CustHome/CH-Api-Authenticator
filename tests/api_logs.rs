mod common;

use axum::http::StatusCode;
use ch_api_authenticator::middleware::tracing::CORRELATION_HEADER;
use ch_api_authenticator::routes::router;
use common::*;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl CaptureWriter {
    fn lines(&self) -> Vec<serde_json::Value> {
        let raw = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("chaque ligne de log est du JSON valide"))
            .collect()
    }

    fn raw(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

async fn with_json_logs<F, T>(fut: F) -> (CaptureWriter, T)
where
    F: Future<Output = T>,
{
    let writer = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        .with_writer(writer.clone())
        .finish();
    let result = fut.with_subscriber(subscriber).await;
    (writer, result)
}

#[tokio::test]
async fn correlation_id_repris_en_echo_dans_la_reponse() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = get(
        router(state),
        "/ping",
        &[(CORRELATION_HEADER, "corr-abc-123")],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.correlation_id.as_deref(),
        Some("corr-abc-123"),
        "le X-Correlation-ID entrant est renvoyé en écho"
    );

    db.drop().await.unwrap();
}

#[tokio::test]
async fn correlation_id_genere_si_absent() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let response = get(router(state), "/ping", &[]).await;

    let generated = response
        .correlation_id
        .expect("un correlation id est généré");

    assert_eq!(generated.len(), 36);

    db.drop().await.unwrap();
}

#[tokio::test]
async fn toutes_les_lignes_de_log_portent_le_correlation_id() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let (writer, _) = with_json_logs(async {
        get(
            router(state.clone()),
            "/validate",
            &[(CORRELATION_HEADER, "corr-log-456")],
        )
        .await
    })
    .await;

    let lines = writer.lines();
    assert!(!lines.is_empty(), "au moins une ligne de log émise");
    for line in &lines {
        assert!(
            line["span"]["correlation_id"] == "corr-log-456"
                || line["spans"].as_array().is_some_and(|spans| spans
                    .iter()
                    .any(|s| s["correlation_id"] == "corr-log-456")),
            "ligne sans correlation_id : {line}"
        );
    }

    db.drop().await.unwrap();
}

#[tokio::test]
async fn log_d_acces_avec_methode_chemin_statut_duree() {
    let db = test_db().await;
    let state = test_state(&db).await;

    let (writer, _) =
        with_json_logs(async { get(router(state.clone()), "/ping", &[]).await }).await;

    let lines = writer.lines();
    let access = lines
        .iter()
        .find(|l| l["fields"]["message"] == "acces")
        .expect("ligne de log d'accès présente");

    assert_eq!(access["fields"]["method"], "GET");
    assert_eq!(access["fields"]["path"], "/ping");
    assert_eq!(access["fields"]["status"], 200);
    assert!(access["fields"]["duration_ms"].is_u64());

    db.drop().await.unwrap();
}

#[tokio::test]
async fn jamais_de_mot_de_passe_ni_token_dans_les_logs() {
    let db = test_db().await;
    let state = test_state(&db).await;
    seed_user(&state, "martin@test.fr", HashMap::new()).await;

    let (writer, token) = with_json_logs(async {
        post_json(
            router(state.clone()),
            "/register",
            r#"{"name": "Leak", "email": "log.leak@test.fr", "password": "Secret-En-Clair-123!"}"#,
            &[],
        )
        .await;
        post_json(
            router(state.clone()),
            "/login",
            r#"{"email": "martin@test.fr", "password": "mauvais-mdp-Visible?"}"#,
            &[],
        )
        .await;
        login_token(&state, "martin@test.fr").await
    })
    .await;

    let raw = writer.raw();
    assert!(
        !raw.contains("Secret-En-Clair-123!"),
        "mot de passe register en clair dans les logs"
    );
    assert!(
        !raw.contains("mauvais-mdp-Visible?"),
        "mot de passe login en clair dans les logs"
    );
    assert!(
        !raw.contains(PASSWORD),
        "mot de passe de seed dans les logs"
    );
    assert!(!raw.contains(&token), "access token dans les logs");
    assert!(!raw.contains("$argon2id$"), "hash dans les logs");

    db.drop().await.unwrap();
}
