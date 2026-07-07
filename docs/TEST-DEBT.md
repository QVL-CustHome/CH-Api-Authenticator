# Dette de tests — CH-Api-Authenticator

Ces tests d'intégration n'avaient jamais tourné en CI (repo sans pipeline auparavant) et
ont dérivé du code au fil des évolutions. Le job `test` est en `allow_failure: true` le temps
de les remettre à niveau. **Le service et son déploiement ne sont PAS impactés** (lint,
secret-scan, build, deploy sont verts et bloquants).

## Dérives identifiées (2026-07-07)
1. **CGU** (corrigé) : `/register` exige `accepted_terms_version = "v1"`. Corrigé dans
   api_admin.rs, api_login.rs, e2e.rs, e2e_sprint2.rs.
2. **Header IP** (à faire) : `/validate` renvoie 403 sans `CLIENT_IP_HEADER`. Les tests
   `api_validate.rs` (token_valide_200_role_global, user_normal_sans_claim_ip_valide_depuis_partout,
   contrat_gateway_user_id_non_vide_et_role_present) doivent envoyer ce header.
3. **À auditer** : re-passer toute la suite après (1) et (2) car d'autres fichiers peuvent
   révéler des dérives masquées jusqu'ici par un état de base MongoDB partagé.

## Remise à niveau
Lancer en local avec une base isolée + sérialisé :
`cargo test -- --test-threads=1` (chaque test crée déjà une base `ch_auth_test_<id>` unique).
