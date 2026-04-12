use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn compute_hash(json_str: &str) -> String {
    let val: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    let canonical = canonicalize_json(&val);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();
    hex_encode(&hash)
}

#[wasm_bindgen]
pub fn verify_signature(payload_hex: &str, signature_hex: &str, public_key_hex: &str) -> bool {
    let payload = match hex_decode(payload_hex) {
        Some(p) => p,
        None => return false,
    };
    let sig_bytes = match hex_decode(signature_hex) {
        Some(s) => s,
        None => return false,
    };
    let pk_bytes = match hex_decode(public_key_hex) {
        Some(k) => k,
        None => return false,
    };

    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&match pk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    }) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    let signature = match ed25519_dalek::Signature::try_from(sig_bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verifying_key.verify(&payload, &signature).is_ok()
}

#[wasm_bindgen]
pub fn validate_token_format(token_json: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct SignedToken {
        header: String,
        payload: String,
        signature: String,
    }
    let token: SignedToken = match serde_json::from_str(token_json) {
        Ok(t) => t,
        Err(_) => return false,
    };
    token.header == "ag-exec-v1" && !token.payload.is_empty() && !token.signature.is_empty()
}

#[wasm_bindgen]
pub fn decode_claims(token_json: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct SignedToken {
        header: String,
        payload: String,
        signature: String,
    }
    let token: SignedToken = serde_json::from_str(token_json).ok()?;
    if token.header != "ag-exec-v1" {
        return None;
    }
    use base64::Engine;
    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(&token.payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    Some(claims.to_string())
}

fn canonicalize_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<_> = map.iter().collect();
            pairs.sort_by_key(|(k, _)| *k);
            let inner: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{}:{}", k, canonicalize_json(v)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonicalize_json).collect();
            format!("[{}]", inner.join(","))
        }
        serde_json::Value::String(s) => format!("\"{}\"", s),
        other => other.to_string(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

mod base64 {
    pub mod engine {
        pub mod general_purpose {
            pub struct STANDARD;
            pub trait Engine {
                fn decode(&self, input: &str) -> Result<Vec<u8>, DecodeError>;
                fn encode(&self, input: &[u8]) -> String;
            }
            impl Engine for STANDARD {
                fn decode(&self, input: &str) -> Result<Vec<u8>, DecodeError> {
                    fn decode_char(c: u8) -> Option<u8> {
                        match c {
                            b'A'..=b'Z' => Some(c - b'A'),
                            b'a'..=b'z' => Some(c - b'a' + 26),
                            b'0'..=b'9' => Some(c - b'0' + 52),
                            b'+' => Some(62),
                            b'/' => Some(63),
                            b'=' => None,
                            _ => None,
                        }
                    }
                    let input = input.as_bytes();
                    let mut result = Vec::with_capacity(input.len() * 3 / 4);
                    let mut buf = [0u8; 4];
                    let mut buf_idx = 0;
                    for &c in input {
                        if c == b'=' {
                            break;
                        }
                        match decode_char(c) {
                            Some(v) => {
                                buf[buf_idx] = v;
                                buf_idx += 1;
                                if buf_idx == 4 {
                                    result.push(buf[0] << 2 | buf[1] >> 4);
                                    result.push((buf[1] & 0xF) << 4 | buf[2] >> 2);
                                    result.push((buf[2] & 0x3) << 6 | buf[3]);
                                    buf_idx = 0;
                                }
                            }
                            None => return Err(DecodeError),
                        }
                    }
                    if buf_idx >= 2 {
                        result.push(buf[0] << 2 | buf[1] >> 4);
                    }
                    if buf_idx >= 3 {
                        result.push((buf[1] & 0xF) << 4 | buf[2] >> 2);
                    }
                    Ok(result)
                }
                fn encode(&self, _input: &[u8]) -> String {
                    String::new()
                }
            }
            #[derive(Debug)]
            pub struct DecodeError;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash_deterministic() {
        let h1 = compute_hash(r#"{"command": "ls", "args": ["-la"]}"#);
        let h2 = compute_hash(r#"{"command": "ls", "args": ["-la"]}"#);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_compute_hash_key_order() {
        let h1 = compute_hash(r#"{"b": 2, "a": 1}"#);
        let h2 = compute_hash(r#"{"a": 1, "b": 2}"#);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_validate_token_format() {
        let valid = r#"{"header": "ag-exec-v1", "payload": "abc", "signature": "def"}"#;
        assert!(validate_token_format(valid));
        let invalid_header = r#"{"header": "wrong", "payload": "abc", "signature": "def"}"#;
        assert!(!validate_token_format(invalid_header));
        let bad_json = "not json";
        assert!(!validate_token_format(bad_json));
    }

    #[test]
    fn test_invalid_json_returns_empty() {
        assert_eq!(compute_hash("not json"), "");
    }
}
