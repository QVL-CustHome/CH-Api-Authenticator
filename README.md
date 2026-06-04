# CH-Api-Authenticator

Microservice d'authentification **multi-portail** de l'écosystème CustHome (Rust / Axum / MongoDB).

Il est appelé par [CH-Api-GateWay](https://github.com/QVL-CustHome/CH-Api-GateWay) :
- pour **chaque requête protégée** : `GET /validate` (contrat : réponse < 100 ms, validation JWT sans I/O) ;
- pour les routes publiques `/api/auth/*` proxifiées (login, register…).

## Concepts clés

- **Rôles par portail** : un utilisateur porte une map `{ portail → rôle }` ; la Gateway transmet
  le portail visé via le header `X-Portal`, l'Authenticator résout le rôle correspondant.
- **Super-admin global** : flag au-dessus des portails (admin partout).
- **Whitelist IP par utilisateur** : `whitelist_only` + `allowed_ips` (CIDR), vérifiée au login,
  token lié à l'IP (claim `ip`) contrôlé au `/validate` via `X-Client-IP`.
- **JWT stateless HS256** (TTL 15 min) + cookie `HttpOnly` posé au login.

## Endpoints (sprint en cours)

| Méthode | Route | Description |
|---|---|---|
| `POST` | `/register` | Inscription (Argon2id) |
| `POST` | `/login` | Connexion → JWT + cookie HttpOnly |
| `GET` | `/validate` | Validation du token pour la Gateway (`X-Portal`, `X-Client-IP`) |
| `GET` | `/health` | État du service (+ ping MongoDB) |
| `GET` | `/ping` | Route témoin |

## Développement

Prérequis : Rust stable, MongoDB locale (service — pas de Docker).

```sh
cp .env.example .env   # renseigner JWT_SECRET (>= 32 octets), MONGO_URI, ADMIN_*
cargo run              # démarre sur :8081
cargo test             # tests (les tests d'intégration utilisent la MongoDB locale)
```

Configuration : `config.toml` (non sensible, surcharge par variables `CH__*`) + secrets via environnement.
Le premier super-admin est créé au démarrage depuis `ADMIN_EMAIL` / `ADMIN_PASSWORD` (idempotent).

## Suivi

Sprint Jira « Api Authenticator » — projet [CustHome (SCRUM)](https://martinqueval04.atlassian.net/jira/software/projects/SCRUM/boards/1).
