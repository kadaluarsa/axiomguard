use sha2::{Digest, Sha256};

pub struct IntegrityCheck {
    hash: String,
    text_section_size: usize,
}

impl IntegrityCheck {
    pub fn new() -> Self {
        let (hash, size) = match Self::compute_hash() {
            Some((h, s)) => (h, s),
            None => ("integrity-check-unavailable".to_string(), 0),
        };
        Self {
            hash,
            text_section_size: size,
        }
    }

    pub fn verify(&self) -> bool {
        match Self::compute_hash() {
            Some((current_hash, _)) => current_hash == self.hash,
            None => false,
        }
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    fn compute_hash() -> Option<(String, usize)> {
        let exe_path = std::env::current_exe().ok()?;
        let data = std::fs::read(&exe_path).ok()?;
        let size = data.len();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();
        Some((format!("{:x}", result), size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_check_runs_without_panic() {
        let check = IntegrityCheck::new();
        assert!(!check.hash().is_empty());
    }
}
