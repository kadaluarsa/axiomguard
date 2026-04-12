use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::sync::{Mutex, RwLock};
pub fn generate_signing_key() -> SigningKey {
    let mut csprng = OsRng;
    SigningKey::generate(&mut csprng)
}

pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub fn export_verifying_key(key: &VerifyingKey) -> String {
    let bytes = key.to_bytes();
    let mut hex = String::with_capacity(64);
    for byte in &bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

pub fn verifying_key_from_hex(hex: &str) -> Option<VerifyingKey> {
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

pub struct KeyManager {
    current: Mutex<SigningKey>,
    previous: RwLock<Option<VerifyingKey>>,
}

impl KeyManager {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            current: Mutex::new(SigningKey::from_bytes(&seed)),
            previous: RwLock::new(None),
        }
    }

    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        self.current
            .lock()
            .expect("key lock poisoned")
            .sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &ed25519_dalek::Signature) -> bool {
        let current_vk = self
            .current
            .lock()
            .expect("key lock poisoned")
            .verifying_key();
        if current_vk.verify(message, signature).is_ok() {
            return true;
        }
        let prev_guard = self.previous.read().expect("key lock poisoned");
        if let Some(prev_vk) = *prev_guard {
            return prev_vk.verify(message, signature).is_ok();
        }
        false
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.current
            .lock()
            .expect("key lock poisoned")
            .verifying_key()
    }

    pub fn rotate(&self) -> VerifyingKey {
        let old_vk = self.verifying_key();
        let new_key = generate_signing_key();
        let new_vk = new_key.verifying_key();

        *self.previous.write().expect("key lock poisoned") = Some(old_vk);
        *self.current.lock().expect("key lock poisoned") = new_key;

        tracing::info!(
            old_key = %export_verifying_key(&old_vk),
            new_key = %export_verifying_key(&new_vk),
            "signing key rotated"
        );
        new_vk
    }

    pub fn signing_key_hex(&self) -> String {
        export_verifying_key(&self.verifying_key())
    }
}

pub trait KmsProvider: Send + Sync {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn verifying_key(&self) -> Result<VerifyingKey, Box<dyn std::error::Error>>;
}

pub struct LocalKms {
    signing_key: SigningKey,
}

impl LocalKms {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }
}

impl KmsProvider for LocalKms {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let sig = self.signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verifying_key(&self) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
        Ok(self.signing_key.verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_roundtrip() {
        let signing = generate_signing_key();
        let verifying = signing.verifying_key();
        let hex = export_verifying_key(&verifying);
        let restored = verifying_key_from_hex(&hex).unwrap();
        assert_eq!(verifying, restored);
    }

    #[test]
    fn test_deterministic_from_seed() {
        let seed = [42u8; 32];
        let key1 = signing_key_from_seed(&seed);
        let key2 = signing_key_from_seed(&seed);
        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_key_manager_sign_verify() {
        let km = KeyManager::new([1u8; 32]);
        let msg = b"test message";
        let sig = km.sign(msg);
        assert!(km.verify(msg, &sig));
    }

    #[test]
    fn test_key_rotation_accepts_old_key() {
        let km = KeyManager::new([1u8; 32]);
        let msg = b"important message";
        let sig = km.sign(msg);

        km.rotate();

        assert!(km.verify(msg, &sig));
    }

    #[test]
    fn test_key_rotation_new_key_works() {
        let km = KeyManager::new([1u8; 32]);
        km.rotate();
        let msg = b"after rotation";
        let sig = km.sign(msg);
        assert!(km.verify(msg, &sig));
    }

    #[test]
    fn test_local_kms_sign_verify() {
        let kms = LocalKms::from_seed(&[77u8; 32]);
        let msg = b"kms test";
        let sig_bytes = kms.sign(msg).unwrap();
        let vk = kms.verifying_key().unwrap();

        let sig = ed25519_dalek::Signature::try_from(sig_bytes.as_slice()).unwrap();
        assert!(vk.verify(msg, &sig).is_ok());
    }
}
