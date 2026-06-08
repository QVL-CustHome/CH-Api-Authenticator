//! CH-Api-Authenticator — microservice d'authentification multi-portail CustHome.
//!
//! Exposé en bibliothèque pour que la suite d'intégration `tests/` construise
//! le routeur et l'état applicatif comme le ferait le binaire.

pub mod config;
pub mod domain;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod repository;
pub mod routes;
pub mod services;
pub mod state;
pub mod validation;
