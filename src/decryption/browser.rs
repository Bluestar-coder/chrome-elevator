// 浏览器配置和管理
use std::path::PathBuf;
use anyhow::Result;
use crate::obf_str;

#[derive(Debug, Clone)]
pub struct BrowserConfig {
    pub name: String,
    pub display_name: String,
    pub process_name: String,
    pub user_data_path: PathBuf,
}

impl BrowserConfig {
    /// 获取 Chrome 配置
    pub fn chrome() -> Self {
        Self {
            name: obf_str!("chrome"),
            display_name: obf_str!("Chrome"),
            process_name: obf_str!("chrome.exe"),
            user_data_path: get_local_appdata()
                .join(obf_str!("Google"))
                .join(obf_str!("Chrome"))
                .join(&*crate::obfuscation::USER_DATA),
        }
    }
    
    /// 获取 Brave 配置
    pub fn brave() -> Self {
        Self {
            name: obf_str!("brave"),
            display_name: obf_str!("Brave"),
            process_name: obf_str!("brave.exe"),
            user_data_path: get_local_appdata()
                .join(obf_str!("BraveSoftware"))
                .join(obf_str!("Brave-Browser"))
                .join(&*crate::obfuscation::USER_DATA),
        }
    }
    
    /// 获取 Edge 配置
    pub fn edge() -> Self {
        Self {
            name: obf_str!("edge"),
            display_name: obf_str!("Edge"),
            process_name: obf_str!("msedge.exe"),
            user_data_path: get_local_appdata()
                .join(obf_str!("Microsoft"))
                .join(obf_str!("Edge"))
                .join(&*crate::obfuscation::USER_DATA),
        }
    }
    
    /// 根据名称获取配置
    pub fn from_name(name: &str) -> Result<Self> {
        match name.to_lowercase().as_str() {
            "chrome" => Ok(Self::chrome()),
            "brave" => Ok(Self::brave()),
            "edge" => Ok(Self::edge()),
            _ => anyhow::bail!("Unknown browser: {}", name),
        }
    }
    
    /// 获取 Local State 文件路径
    pub fn local_state_path(&self) -> PathBuf {
        self.user_data_path.join(&*crate::obfuscation::LOCAL_STATE)
    }
    
    /// 检查浏览器是否已安装
    pub fn is_installed(&self) -> bool {
        self.user_data_path.exists() && self.local_state_path().exists()
    }
}

/// 获取 LocalAppData 路径
#[cfg(target_os = "windows")]
fn get_local_appdata() -> PathBuf {
    use windows::Win32::UI::Shell::*;
    use windows::core::PWSTR;
    
    unsafe {
        let mut path: PWSTR = PWSTR::null();
        if SHGetKnownFolderPath(
            &FOLDERID_LocalAppData,
            KNOWN_FOLDER_FLAG(0),
            None,
            &mut path,
        ).is_ok() {
            let path_str = path.to_string().unwrap_or_default();
            return PathBuf::from(path_str);
        }
    }
    
    // 回退方案
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Users\Default\AppData\Local"))
}

#[cfg(not(target_os = "windows"))]
fn get_local_appdata() -> PathBuf {
    PathBuf::from("/tmp")
}

/// 发现所有已安装的浏览器
pub fn discover_installed_browsers() -> Vec<BrowserConfig> {
    vec![
        BrowserConfig::chrome(),
        BrowserConfig::brave(),
        BrowserConfig::edge(),
    ]
    .into_iter()
    .filter(|config| config.is_installed())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_browser_config_creation() {
        let chrome = BrowserConfig::chrome();
        assert_eq!(chrome.name, "chrome");
        assert!(chrome.user_data_path.to_string_lossy().contains("Chrome"));
    }
    
    #[test]
    fn test_from_name() {
        assert!(BrowserConfig::from_name("chrome").is_ok());
        assert!(BrowserConfig::from_name("brave").is_ok());
        assert!(BrowserConfig::from_name("edge").is_ok());
        assert!(BrowserConfig::from_name("invalid").is_err());
    }
}
