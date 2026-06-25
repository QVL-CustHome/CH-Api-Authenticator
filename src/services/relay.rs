use crate::config::{RelayConfig, Secrets};
use crate::domain::events::{USER_DELETED_TOPIC, UserDeletedEvent};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::{AsyncClient, Event, MqttOptions};
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("clé privée RS256 manquante (RELAY_JWT_PRIVATE_KEY) alors que relay.enabled = true")]
    MissingSigningKey,
    #[error("clé privée RS256 invalide : {0}")]
    InvalidSigningKey(String),
}

#[derive(Serialize)]
struct RelayClaims<'a> {
    sub: &'a str,
    roles: &'a [String],
    iss: &'a str,
    iat: u64,
    exp: u64,
}

pub enum RelayPublisher {
    Disabled,
    Connected(AsyncClient),
}

impl RelayPublisher {
    pub fn from_settings(config: &RelayConfig, secrets: &Secrets) -> Result<Self, RelayError> {
        if !config.enabled {
            return Ok(RelayPublisher::Disabled);
        }

        let private_key = secrets
            .relay_jwt_private_key
            .as_deref()
            .ok_or(RelayError::MissingSigningKey)?;
        let signing_key = EncodingKey::from_rsa_pem(private_key.as_bytes())
            .map_err(|e| RelayError::InvalidSigningKey(e.to_string()))?;

        let roles = vec!["auth".to_string()];
        let token_ttl = Duration::from_secs(config.token_ttl_seconds);
        let token = sign_relay_token(&config.identity, &roles, &signing_key, token_ttl)
            .map_err(|e| RelayError::InvalidSigningKey(e.to_string()))?;

        let mut options =
            MqttOptions::new(config.client_id.clone(), config.host.clone(), config.port);
        options.set_clean_start(true);
        options.set_keep_alive(Duration::from_secs(30));
        options.set_credentials(config.identity.clone(), token);

        let (client, mut eventloop) = AsyncClient::new(options, 16);

        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(Event::Incoming(_)) | Ok(Event::Outgoing(_)) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "Boucle MQTT Relay en erreur, reconnexion");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });

        Ok(RelayPublisher::Connected(client))
    }

    pub async fn publish_user_deleted(&self, event: &UserDeletedEvent) {
        let RelayPublisher::Connected(client) = self else {
            tracing::info!(
                topic = USER_DELETED_TOPIC,
                sub = %event.sub,
                event_id = %event.event_id,
                "Relay désactivé : event auth/user/deleted non publié"
            );
            return;
        };

        let payload = match serde_json::to_vec(event) {
            Ok(payload) => payload,
            Err(e) => {
                tracing::error!(error = %e, "Sérialisation de l'event auth/user/deleted en échec");
                return;
            }
        };

        let result = client
            .publish(USER_DELETED_TOPIC, QoS::AtLeastOnce, false, payload)
            .await;

        match result {
            Ok(()) => tracing::info!(
                topic = USER_DELETED_TOPIC,
                sub = %event.sub,
                event_id = %event.event_id,
                "Event auth/user/deleted publié sur Relay"
            ),
            Err(e) => tracing::error!(
                error = %e,
                topic = USER_DELETED_TOPIC,
                sub = %event.sub,
                event_id = %event.event_id,
                "Publication de l'event auth/user/deleted en échec, suppression déjà persistée"
            ),
        }
    }
}

fn sign_relay_token(
    identity: &str,
    roles: &[String],
    signing_key: &EncodingKey,
    token_ttl: Duration,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = unix_now();
    let claims = RelayClaims {
        sub: identity,
        roles,
        iss: identity,
        iat: now,
        exp: now + token_ttl.as_secs(),
    };
    jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, signing_key)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
