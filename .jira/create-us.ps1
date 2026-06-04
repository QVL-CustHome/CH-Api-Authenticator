# Création des US du sprint "Api Authenticator" (board 1, sprint 3) via acli.
# Usage : .\create-us.ps1 -From 0 -To 0   (test sur la première US)
#         .\create-us.ps1 -From 1 -To 12  (le reste)
param([int]$From = 0, [int]$To = 12)

$SPRINT_FIELD = "customfield_10020"  # champ Sprint (Jira Cloud team-managed)
$SPRINT_ID = 3
$PROJECT = "SCRUM"

$tickets = @(
    @{
        Summary = "[US-00] Mise en place du projet (Rust/Axum + MongoDB)"
        Labels = @("api-authenticator", "setup", "rust", "mongodb")
        Story = "En tant que developpeur, je veux un socle projet operationnel (Rust/Axum + MongoDB) afin de developper les US suivantes sans friction."
        Criteria = @(
            "Projet Cargo initialise avec arborescence modulaire : handlers/, services/, repository/, domain/, middleware/",
            "Dependances : axum, tokio, mongodb, argon2, jsonwebtoken, serde, validator, tracing, figment, ipnet, tower-http",
            "docker-compose.yml fournissant un MongoDB local avec volume persistant",
            "config.toml (port 8081, log_level, TTL token, nom du cookie) + .env.example (JWT_SECRET, MONGO_URI, ADMIN_EMAIL, ADMIN_PASSWORD)",
            "Aucun secret commite ; surcharge variables d'environnement > fichier de config",
            "Echec au demarrage avec message explicite si configuration invalide ou secret manquant (JWT_SECRET >= 32 octets)",
            "cargo run demarre un serveur Axum qui repond ; cargo fmt, cargo clippy et cargo test passent"
        )
    },
    @{
        Summary = "[US-01] Connexion MongoDB et modele utilisateur"
        Labels = @("api-authenticator", "mongodb", "modele-utilisateur")
        Story = "En tant que systeme, je veux persister les utilisateurs dans MongoDB afin de gerer comptes, roles par portail et whitelist IP."
        Criteria = @(
            "Collection users : email (unique, lowercase), password_hash, roles (map portail -> role), is_super_admin, whitelist_only (defaut false), allowed_ips, created_at, updated_at",
            "Index unique sur email cree au demarrage",
            "Seed du premier super-admin via ADMIN_EMAIL / ADMIN_PASSWORD (cree uniquement s'il n'existe pas deja)",
            "Echec controle et logge si MongoDB est injoignable au demarrage",
            "Test repository : insertion d'un email en doublon -> erreur de duplication propre"
        )
    },
    @{
        Summary = "[US-02] Inscription (POST /register)"
        Labels = @("api-authenticator", "auth", "inscription", "securite")
        Story = "En tant que visiteur, je veux creer un compte avec email et mot de passe afin d'acceder aux portails CustHome."
        Criteria = @(
            "Validation : format email + mot de passe >= 8 caracteres -> 400 sinon",
            "Hash Argon2id (le hash en base commence par `$argon2id`$) ; jamais de mot de passe en clair, ni en base ni en logs",
            "Email normalise en lowercase avant insertion",
            "roles initialises depuis registration.default_roles de la config (vide par defaut) ; jamais acceptes depuis le body de la requete",
            "201 {user_id} | 409 si email deja utilise | 400 si payload invalide"
        )
    },
    @{
        Summary = "[US-03] Connexion (POST /login) - JWT + cookie HttpOnly"
        Labels = @("api-authenticator", "auth", "login", "jwt", "cookie")
        Story = "En tant qu'utilisateur, je veux obtenir un token contre mes identifiants afin de naviguer sur les portails."
        Criteria = @(
            "Verification du mot de passe via Argon2id",
            "401 generique strictement identique pour email inconnu et mot de passe errone (anti-enumeration)",
            "JWT HS256 avec claims : sub (user_id), roles (map portail -> role), iat, exp (TTL configurable, 15 min par defaut)",
            "Reponse 200 {access_token, token_type: Bearer, expires_in}",
            "Set-Cookie HttpOnly contenant le token (attributs Secure et SameSite configurables pour le dev local)",
            "Aucun token, hash ou mot de passe dans les logs"
        )
    },
    @{
        Summary = "[US-04] Restriction par whitelist IP au login"
        Labels = @("api-authenticator", "securite", "whitelist-ip")
        Story = "En tant qu'administrateur, je veux restreindre certains comptes a des IP autorisees afin de durcir l'acces des comptes sensibles."
        Criteria = @(
            "Champs utilisateur : whitelist_only (defaut false) et allowed_ips (IP simples et plages CIDR)",
            "Au login : si whitelist_only = true et X-Client-IP absente ou hors allowed_ips -> 401 generique (indistinguable d'un mauvais mot de passe)",
            "Si whitelist_only = true : claim ip (IP de login) ajoute au JWT pour verification au /validate",
            "Parsing CIDR robuste (crate ipnet) ; entree invalide dans allowed_ips loggee en WARN et ignoree",
            "Tests : IP exacte, IP dans un CIDR, IP hors liste, utilisateur sans whitelist non impacte"
        )
    },
    @{
        Summary = "[US-05] Validation du token (GET /validate) - contrat Gateway multi-portail"
        Labels = @("api-authenticator", "jwt", "contrat-gateway", "multi-portail")
        Story = "En tant que Gateway, je veux valider un token en moins de 100 ms afin d'autoriser ou refuser chaque requete protegee."
        Criteria = @(
            "Lecture du header Authorization: Bearer ; verification signature + expiration SANS AUCUNE I/O (ni base ni reseau)",
            "Resolution du role : roles[X-Portal] -> 200 {user_id, role} ; aucun role sur ce portail -> 403 ; is_super_admin -> admin sur tous les portails",
            "Token absent, malforme, expire ou signature invalide -> 401",
            "Si claim ip present dans le token : comparaison avec X-Client-IP -> 401 si differente",
            "Test d'integration reproduisant le client Go de la Gateway (middleware auth.go) : decodage de {user_id, role}",
            "Latence locale p99 < 10 ms"
        )
    },
    @{
        Summary = "[US-06] Logs JSON structures et Correlation ID"
        Labels = @("api-authenticator", "observabilite", "logs")
        Story = "En tant qu'operateur, je veux des logs JSON correles avec ceux de la Gateway afin de tracer une requete de bout en bout."
        Criteria = @(
            "tracing avec sortie JSON ; niveau configurable (DEBUG/INFO/WARN/ERROR, coherent avec la Gateway)",
            "X-Correlation-ID entrant attache a toutes les lignes de log de la requete",
            "Log d'acces par requete : methode, chemin, statut HTTP, duree",
            "Jamais de mot de passe, hash, token ou secret dans les logs"
        )
    },
    @{
        Summary = "[US-07] Health check (GET /health)"
        Labels = @("api-authenticator", "observabilite", "health")
        Story = "En tant qu'operateur, je veux connaitre l'etat du service afin de superviser la plateforme."
        Criteria = @(
            "200 {status: ok | degraded, version} ; degraded si le ping MongoDB echoue",
            "GET /validate reste pleinement fonctionnel quand MongoDB est down (validation stateless)",
            "Endpoint accessible sans authentification"
        )
    },
    @{
        Summary = "[US-08] Tests d'integration de bout en bout"
        Labels = @("api-authenticator", "tests", "contrat-gateway")
        Story = "En tant qu'equipe, je veux une suite d'integration verrouillant le contrat afin d'eviter toute regression vis-a-vis de la Gateway."
        Criteria = @(
            "Scenario nominal : register -> login -> validate avec resolution correcte du role par portail",
            "Cas d'erreur : token expire, signature falsifiee, header manquant, portail sans role (403), whitelist KO",
            "Verification du cookie HttpOnly pose au login",
            "cargo test vert, executable en CI (MongoDB ephemere via Docker)"
        )
    },
    @{
        Summary = "[US-09] Gateway - Portail par route et header X-Portal"
        Labels = @("api-gateway", "multi-portail", "contrat-gateway")
        Story = "En tant que Gateway, je veux identifier le portail de chaque route afin que l'Authenticator resolve le bon role utilisateur."
        Criteria = @(
            "Nouveau champ portal sur chaque route de config.yaml",
            "Appel GET /validate enrichi du header X-Portal",
            "Validation au demarrage : route avec require_auth = true sans portal -> erreur de configuration explicite",
            "Tests du middleware auth mis a jour"
        )
    },
    @{
        Summary = "[US-10] Gateway - Transmission de l'IP client (X-Client-IP)"
        Labels = @("api-gateway", "securite", "whitelist-ip")
        Story = "En tant qu'Authenticator, je veux recevoir l'IP client reelle afin d'appliquer la whitelist IP par utilisateur."
        Criteria = @(
            "Header X-Client-IP envoye au /validate ET aux routes proxifiees vers l'Authenticator (login)",
            "IP resolue via la logique trusted_proxies existante (US-13 du sprint Api Gateway)",
            "X-Client-IP entrant depuis l'exterieur purge systematiquement (header de confiance, comme X-User-*)",
            "Tests : avec et sans proxy de confiance"
        )
    },
    @{
        Summary = "[US-11] Gateway - Extraction du token depuis un cookie HttpOnly"
        Labels = @("api-gateway", "cookie", "auth")
        Story = "En tant qu'utilisateur sur navigateur, je veux que ma session en cookie HttpOnly soit reconnue afin de naviguer sans gerer de header."
        Criteria = @(
            "Token lu depuis un cookie (nom configurable, ex: ch_token) avec fallback sur le header Authorization ; le header prime s'il est present",
            "Token transmis a l'Authenticator en Authorization: Bearer (contrat /validate inchange)",
            "Tests : cookie seul, header seul, les deux, aucun"
        )
    },
    @{
        Summary = "[US-12] Gateway - Redirection des navigateurs non authentifies"
        Labels = @("api-gateway", "redirection", "front-auth")
        Story = "En tant qu'utilisateur non connecte sur un navigateur, je veux etre redirige vers la page d'authentification afin de me connecter."
        Criteria = @(
            "Nouvelle config auth_front_url",
            "Sur 401 : si Accept contient text/html -> 302 Location {auth_front_url}?redirect={url d'origine encodee} ; sinon 401 JSON inchange pour les appels API",
            "Aucune boucle de redirection possible (routes publiques /api/auth exclues du mecanisme)",
            "Tests : navigateur redirige, appel API 401 JSON"
        )
    }
)

function New-AdfDescription($story, $criteria) {
    $bullets = @($criteria | ForEach-Object {
        @{ type = "listItem"; content = @(@{ type = "paragraph"; content = @(@{ type = "text"; text = $_ }) }) }
    })
    return @{
        type = "doc"; version = 1
        content = @(
            @{ type = "paragraph"; content = @(@{ type = "text"; text = $story; marks = @(@{ type = "em" }) }) },
            @{ type = "heading"; attrs = @{ level = 3 }; content = @(@{ type = "text"; text = "Criteres d'acceptation" }) },
            @{ type = "bulletList"; content = $bullets }
        )
    }
}

for ($i = $From; $i -le $To; $i++) {
    $t = $tickets[$i]
    $payload = @{
        projectKey = $PROJECT
        type = "Story"
        summary = $t.Summary
        labels = $t.Labels
        description = New-AdfDescription $t.Story $t.Criteria
        additionalAttributes = @{ $SPRINT_FIELD = $SPRINT_ID }
    }
    $file = Join-Path $PSScriptRoot ("us-{0:d2}.json" -f $i)
    $payload | ConvertTo-Json -Depth 20 | Out-File $file -Encoding ascii
    Write-Host "--- Creation $($t.Summary)"
    acli jira workitem create --from-json $file
    if (-not $?) { Write-Host "ECHEC sur l'index $i" -ForegroundColor Red; exit 1 }
}
