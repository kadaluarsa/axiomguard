use rand::Rng;
use sha2::{Digest, Sha256};

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn generate_api_key() -> (String, String, String) {
    let suffix: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let prefix = "ag_".to_string();
    let full_key = format!("{}{}", prefix, suffix);
    let key_hash = sha256_hex(&full_key);
    (full_key, key_hash, prefix)
}
