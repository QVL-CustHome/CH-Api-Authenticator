# Versionnement de l'API — CH-Api-Authenticator

## Convention

- Les routes **publiques** sont exposées sous le préfixe `/v1` (`API_VERSION_PREFIX`).
- Les routes **opérationnelles** (`/health`, `/ping`) ne sont pas versionnées : ce sont des sondes d'infrastructure, hors contrat applicatif.
- Les routes **internes** (`/internal/...`) ne sont pas versionnées : elles relèvent d'un contrat inter-services privé, géré par déploiement coordonné, pas par négociation de version client.

## Stratégie de transition

Double exposition temporaire :

- Les routes publiques restent accessibles **sans préfixe** (chemins historiques) pour ne pas casser les consommateurs existants.
- Elles sont **simultanément** disponibles sous `/v1/...`.

Les consommateurs migrent vers `/v1`. Les chemins historiques non préfixés seront retirés une fois la migration des consommateurs confirmée (étape ultérieure, hors de cette livraison).

## Routes publiques versionnées

`/register`, `/login`, `/refresh`, `/logout`, `/validate`, `/password`, `/password/forgot`, `/password/reset`, `/settings/registration`, `/me`, `/users` (+ sous-ressources), `/roles` (+ sous-ressources), `/analytics/traffic`.
