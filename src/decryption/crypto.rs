// 加密解密模块
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};

pub struct BrowserCrypto {
    cipher: Aes256Gcm,
}

impl BrowserCrypto {
    /// 创建新的加密器
    pub fn new(master_key: &[u8]) -> Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(master_key)
            .context("Invalid master key length (expected 32 bytes)")?;

        Ok(Self { cipher })
    }

    /// 解密 v10 格式数据 (DPAPI)
    pub fn decrypt_v10(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        // 检查前缀
        if !encrypted.starts_with(b"v10") {
            anyhow::bail!("Invalid v10 prefix");
        }

        // v10 格式: "v10" + nonce(12) + ciphertext + tag(16)
        if encrypted.len() < 3 + 12 + 16 {
            anyhow::bail!("Data too short for v10 format");
        }

        let nonce = Nonce::from_slice(&encrypted[3..15]);
        let ciphertext = &encrypted[15..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {}", e))
    }

    /// 解密 v20 格式数据 (ABE)
    pub fn decrypt_v20(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if !encrypted.starts_with(b"v20") {
            anyhow::bail!("Invalid v20 prefix");
        }

        // v20 格式与 v10 相同
        if encrypted.len() < 3 + 12 + 16 {
            anyhow::bail!("Data too short for v20 format");
        }

        let nonce = Nonce::from_slice(&encrypted[3..15]);
        let ciphertext = &encrypted[15..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {}", e))
    }

    /// 自动检测并解密
    pub fn decrypt_auto(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.starts_with(b"v10") {
            self.decrypt_v10(encrypted)
        } else if encrypted.starts_with(b"v20") {
            self.decrypt_v20(encrypted)
        } else {
            anyhow::bail!("Unknown encryption format (expected v10 or v20 prefix)")
        }
    }
}

/// 从 Base64 解码加密的主密钥
#[allow(dead_code)]
pub fn decode_encrypted_key(base64_key: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};

    general_purpose::STANDARD
        .decode(base64_key)
        .context("Failed to decode base64 encrypted key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_creation() {
        let key = [0u8; 32];
        let crypto = BrowserCrypto::new(&key);
        assert!(crypto.is_ok());
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0u8; 16]; // 错误的长度
        let crypto = BrowserCrypto::new(&key);
        assert!(crypto.is_err());
    }
}
