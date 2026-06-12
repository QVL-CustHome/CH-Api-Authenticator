use crate::config::{EmailMode, Settings};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct SentEmail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

pub enum Mailer {
    Dev,
    Smtp {
        transport: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
    },
    Memory(Arc<Mutex<Vec<SentEmail>>>),
}

impl Mailer {

    pub fn from_settings(settings: &Settings) -> Result<Self, String> {
        match settings.config.email.mode {
            EmailMode::Dev => Ok(Mailer::Dev),
            EmailMode::Smtp => {
                let from: Mailbox = settings.config.email.from.parse().map_err(|e| {
                    format!("email.from {:?} invalide : {e}", settings.config.email.from)
                })?;
                let host = settings
                    .secrets
                    .smtp_host
                    .as_deref()
                    .ok_or("SMTP_HOST requis en mode smtp")?;

                let mut builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                    .map_err(|e| format!("configuration SMTP invalide ({host}) : {e}"))?;
                if let Some(port) = settings.secrets.smtp_port {
                    builder = builder.port(port);
                }
                if let (Some(user), Some(password)) = (
                    settings.secrets.smtp_user.clone(),
                    settings.secrets.smtp_password.clone(),
                ) {
                    builder = builder.credentials(Credentials::new(user, password));
                }
                Ok(Mailer::Smtp {
                    transport: builder.build(),
                    from,
                })
            }
        }
    }

    pub fn memory() -> (Self, Arc<Mutex<Vec<SentEmail>>>) {
        let outbox = Arc::new(Mutex::new(Vec::new()));
        (Mailer::Memory(outbox.clone()), outbox)
    }

    pub async fn send(&self, to: &str, subject: &str, body: &str) {
        match self {
            Mailer::Dev => {
                tracing::warn!(to, subject, body, "EMAIL non envoyé (mode dev)");
            }
            Mailer::Memory(outbox) => {
                outbox.lock().expect("outbox mutex").push(SentEmail {
                    to: to.to_string(),
                    subject: subject.to_string(),
                    body: body.to_string(),
                });
            }
            Mailer::Smtp { transport, from } => {
                let recipient: Mailbox = match to.parse() {
                    Ok(mailbox) => mailbox,
                    Err(e) => {
                        tracing::error!(to, error = %e, "Destinataire illisible, email abandonné");
                        return;
                    }
                };
                let message = match Message::builder()
                    .from(from.clone())
                    .to(recipient)
                    .subject(subject)
                    .body(body.to_string())
                {
                    Ok(message) => message,
                    Err(e) => {
                        tracing::error!(error = %e, "Construction de l'email en échec");
                        return;
                    }
                };
                if let Err(e) = transport.send(message).await {
                    tracing::error!(to, error = %e, "Envoi SMTP en échec");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, EmailConfig, RegistrationConfig, Secrets, ServerConfig, Settings, TokenConfig,
    };

    fn settings(mode: EmailMode, from: &str, smtp_host: Option<&str>) -> Settings {
        Settings {
            config: Config {
                server: ServerConfig {
                    port: 0,
                    log_level: "INFO".to_string(),
                },
                token: TokenConfig {
                    ttl_minutes: 15,
                    cookie_name: "ch_token".to_string(),
                    cookie_secure: false,
                    refresh_ttl_days: 7,
                    refresh_cookie_name: "ch_refresh".to_string(),
                },
                registration: RegistrationConfig::default(),
                email: EmailConfig {
                    mode,
                    from: from.to_string(),
                },
                password_reset: crate::config::PasswordResetConfig::default(),
            },
            secrets: Secrets {
                jwt_secret: "un-secret-de-test-suffisamment-long!!!!!".to_string(),
                mongo_uri: "mongodb://localhost:27017/test".to_string(),
                admin_email: None,
                admin_password: None,
                smtp_host: smtp_host.map(str::to_string),
                smtp_port: None,
                smtp_user: None,
                smtp_password: None,
            },
        }
    }

    #[test]
    fn mode_dev_construit_sans_aucun_secret_smtp() {
        let mailer = Mailer::from_settings(&settings(EmailMode::Dev, "CustHome <a@b.fr>", None));
        assert!(matches!(mailer, Ok(Mailer::Dev)));
    }

    #[test]
    fn mode_smtp_sans_host_erreur_explicite() {
        let err = Mailer::from_settings(&settings(EmailMode::Smtp, "CustHome <a@b.fr>", None))
            .err()
            .expect("doit échouer");
        assert!(err.contains("SMTP_HOST"), "erreur : {err}");
    }

    #[test]
    fn from_invalide_erreur_explicite() {
        let err = Mailer::from_settings(&settings(
            EmailMode::Smtp,
            "pas-un-expediteur",
            Some("smtp.test.fr"),
        ))
        .err()
        .expect("doit échouer");
        assert!(err.contains("email.from"), "erreur : {err}");
    }

    #[tokio::test]
    async fn mode_smtp_complet_construit() {
        let mailer = Mailer::from_settings(&settings(
            EmailMode::Smtp,
            "CustHome <no-reply@custhome.fr>",
            Some("smtp.test.fr"),
        ));
        assert!(matches!(mailer, Ok(Mailer::Smtp { .. })));
    }

    #[tokio::test]
    async fn memory_capture_les_envois() {
        let (mailer, outbox) = Mailer::memory();
        mailer
            .send("martin@test.fr", "Sujet", "Corps avec lien")
            .await;

        let sent = outbox.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "martin@test.fr");
        assert_eq!(sent[0].subject, "Sujet");
        assert_eq!(sent[0].body, "Corps avec lien");
    }

    #[tokio::test]
    async fn mode_dev_logge_l_email_en_warn() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        use tracing::instrument::WithSubscriber;
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for Capture {
            type Writer = Capture;
            fn make_writer(&'a self) -> Capture {
                self.clone()
            }
        }

        let writer = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::WARN)
            .with_writer(writer.clone())
            .finish();

        async {
            Mailer::Dev
                .send(
                    "martin@test.fr",
                    "Réinitialisation",
                    "https://lien-de-reset",
                )
                .await;
        }
        .with_subscriber(subscriber)
        .await;

        let logs = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("WARN"), "le mode dev logge en WARN : {logs}");
        assert!(logs.contains("martin@test.fr"));
        assert!(
            logs.contains("https://lien-de-reset"),
            "le lien doit être visible"
        );
    }
}
