use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

pub fn generate() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_aleatoires_et_url_safe() {
        let t1 = generate();
        let t2 = generate();
        assert_eq!(t1.len(), 64);
        assert_ne!(t1, t2);
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_stable_et_distinct_du_token() {
        let token = generate();
        assert_eq!(hash(&token), hash(&token));
        assert_ne!(hash(&token), token);
        assert_eq!(hash(&token).len(), 64);
    }
}
