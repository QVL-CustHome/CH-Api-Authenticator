use crate::config::{MissiveConfig, Secrets};
use serde::Serialize;
use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

pub struct MissiveClient {
    http: reqwest::Client,
    send_url: String,
    secret: String,
}

#[derive(Serialize)]
struct EmailMessage<'a> {
    channel: &'a str,
    to: &'a str,
    subject: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
}

impl MissiveClient {
    pub fn new(config: &MissiveConfig, secrets: &Secrets) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            send_url: format!("{}/v1/send", config.url.trim_end_matches('/')),
            secret: secrets.missive_api_secret.clone(),
        })
    }

    pub async fn send_email(&self, to: &str, subject: &str, text: &str) {
        let message = EmailMessage {
            channel: "email",
            to,
            subject,
            text: Some(text),
        };

        let response = self
            .http
            .post(&self.send_url)
            .header("x-internal-secret", &self.secret)
            .json(&message)
            .send()
            .await;

        match response {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                tracing::error!(status = %response.status(), "Envoi email via Missive refusé");
            }
            Err(error) => {
                tracing::error!(error = %error, "Appel Missive en échec");
            }
        }
    }
}
