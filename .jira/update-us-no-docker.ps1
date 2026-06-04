# Met à jour SCRUM-20 (US-00) et SCRUM-28 (US-08) : MongoDB locale au lieu de Docker.
$updates = @(
    @{
        Key = "SCRUM-20"
        Story = "En tant que developpeur, je veux un socle projet operationnel (Rust/Axum + MongoDB) afin de developper les US suivantes sans friction."
        Criteria = @(
            "Projet Cargo initialise avec arborescence modulaire : handlers/, services/, repository/, domain/, middleware/",
            "Dependances : axum, tokio, mongodb, argon2, jsonwebtoken, serde, validator, tracing, figment, ipnet, tower-http",
            "Utilise l'instance MongoDB locale installee en service Windows (8.2) - aucun conteneur Docker",
            "config.toml (port 8081, log_level, TTL token, nom du cookie) + .env.example (JWT_SECRET, MONGO_URI, ADMIN_EMAIL, ADMIN_PASSWORD)",
            "Aucun secret commite ; surcharge variables d'environnement > fichier de config",
            "Echec au demarrage avec message explicite si configuration invalide ou secret manquant (JWT_SECRET >= 32 octets)",
            "cargo run demarre un serveur Axum qui repond ; cargo fmt, cargo clippy et cargo test passent"
        )
    },
    @{
        Key = "SCRUM-28"
        Story = "En tant qu'equipe, je veux une suite d'integration verrouillant le contrat afin d'eviter toute regression vis-a-vis de la Gateway."
        Criteria = @(
            "Scenario nominal : register -> login -> validate avec resolution correcte du role par portail",
            "Cas d'erreur : token expire, signature falsifiee, header manquant, portail sans role (403), whitelist KO",
            "Verification du cookie HttpOnly pose au login",
            "cargo test vert, executable en CI (instance MongoDB locale, pas de Docker)"
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

foreach ($u in $updates) {
    $file = Join-Path $PSScriptRoot "desc-$($u.Key).json"
    New-AdfDescription $u.Story $u.Criteria | ConvertTo-Json -Depth 20 | Out-File $file -Encoding ascii
    acli jira workitem edit --key $u.Key --description-file $file --yes
    Remove-Item $file
}
