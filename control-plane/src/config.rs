use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct CpConfig {
    pub bind_address: String,
    pub database_url: String,
    pub signing_key_seed: [u8; 32],
    pub encryption_key: [u8; 32],
    pub api_keys: HashSet<String>,
    pub admin_keys: HashSet<String>,
    pub require_auth: bool,
}

impl CpConfig {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();
        let api_keys_str = std::env::var("CP_API_KEYS").unwrap_or_default();
        let api_keys: HashSet<String> = api_keys_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let admin_keys_str = std::env::var("CP_ADMIN_KEYS").unwrap_or_default();
        let admin_keys: HashSet<String> = admin_keys_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let seed_str = std::env::var("CP_SIGNING_KEY_SEED")
            .expect("CP_SIGNING_KEY_SEED must be set to a 32+ byte secret");
        if seed_str.len() < 32 {
            panic!("CP_SIGNING_KEY_SEED must be at least 32 bytes");
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_str.as_bytes()[..32]);

        let enc_str = std::env::var("CP_ENCRYPTION_KEY")
            .expect("CP_ENCRYPTION_KEY must be set to a 32+ byte secret");
        if enc_str.len() < 32 {
            panic!("CP_ENCRYPTION_KEY must be at least 32 bytes");
        }
        let mut encryption_key = [0u8; 32];
        encryption_key.copy_from_slice(&enc_str.as_bytes()[..32]);

        Self {
            bind_address: std::env::var("CP_BIND_ADDRESS").unwrap_or("0.0.0.0:8080".into()),
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or("postgresql://localhost/axiomguard".into()),
            signing_key_seed: seed,
            encryption_key,
            api_keys,
            admin_keys,
            require_auth: std::env::var("CP_REQUIRE_AUTH")
                .map(|v| v == "true")
                .unwrap_or(true),
        }
    }
}
