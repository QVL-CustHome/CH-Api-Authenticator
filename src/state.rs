use crate::config::Settings;
use crate::repository::login_events::LoginEventRepository;
use crate::repository::refresh_tokens::RefreshTokenRepository;
use crate::repository::reset_tokens::ResetTokenRepository;
use crate::repository::roles::RoleRepository;
use crate::repository::settings::SettingsRepository;
use crate::repository::users::UserRepository;
use crate::services::client_ip::TrustedProxies;
use crate::services::jwt::JwtService;
use crate::services::missive::MissiveClient;
use crate::services::rate_limit::RateLimiters;
use crate::services::relay::RelayPublisher;
use mongodb::Database;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,

    pub db: Database,
    pub users: UserRepository,

    pub roles: RoleRepository,

    pub settings_repo: SettingsRepository,

    pub login_events: LoginEventRepository,

    pub reset_tokens: ResetTokenRepository,

    pub refresh_tokens: RefreshTokenRepository,
    pub jwt: Arc<JwtService>,

    pub missive: Arc<MissiveClient>,

    pub relay: Arc<RelayPublisher>,

    pub trusted_proxies: TrustedProxies,

    pub rate_limiters: Arc<RateLimiters>,
}

impl AppState {
    pub fn new(
        settings: Settings,
        db: Database,
        missive: MissiveClient,
        relay: RelayPublisher,
    ) -> Self {
        let jwt = Arc::new(JwtService::new(
            &settings.secrets.jwt_secret,
            &settings.config.token,
        ));
        let trusted_proxies = TrustedProxies::from_env();
        let rate_limiters = Arc::new(RateLimiters::from_config(&settings.rate_limit));
        Self {
            settings: Arc::new(settings),
            users: UserRepository::new(&db),
            roles: RoleRepository::new(&db),
            settings_repo: SettingsRepository::new(&db),
            login_events: LoginEventRepository::new(&db),
            reset_tokens: ResetTokenRepository::new(&db),
            refresh_tokens: RefreshTokenRepository::new(&db),
            db,
            jwt,
            missive: Arc::new(missive),
            relay: Arc::new(relay),
            trusted_proxies,
            rate_limiters,
        }
    }
}
