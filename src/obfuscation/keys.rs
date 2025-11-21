// 动态密钥派生模块
use sha2::{Sha256, Digest};
use std::sync::OnceLock;
use crate::obf_str;

static DERIVED_KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// 获取加密密钥（基于系统环境派生）
pub fn get_encryption_key() -> &'static [u8; 32] {
    DERIVED_KEY.get_or_init(derive_key)
}

/// 派生密钥
fn derive_key() -> [u8; 32] {
    let mut hasher = Sha256::new();
    
    // 1. 卷序列号
    #[cfg(target_os = "windows")]
    if let Some(serial) = get_volume_serial() {
        hasher.update(serial.to_le_bytes());
    }
    
    // 2. 计算机名
    #[cfg(target_os = "windows")]
    if let Some(name) = get_computer_name() {
        hasher.update(name.as_bytes());
    }
    
    // 3. 处理器信息
    #[cfg(target_os = "windows")]
    if let Some(cpu_info) = get_cpu_info() {
        hasher.update(cpu_info.to_le_bytes());
    }
    
    // 4. 固定盐值（混淆）
    hasher.update(obf_str!("ChromeElevator-2025").as_bytes());
    
    let result = hasher.finalize();
    result.into()
}

#[cfg(target_os = "windows")]
fn get_volume_serial() -> Option<u32> {
    use windows::core::PWSTR;
    use windows::Win32::Storage::FileSystem::GetVolumeInformationW;
    
    let mut serial = 0u32;
    unsafe {
        GetVolumeInformationW(
            windows::core::w!("C:\\"),
            PWSTR::null(),
            0,
            Some(&mut serial),
            None,
            None,
            PWSTR::null(),
            0,
        ).ok()?;
    }
    Some(serial)
}

#[cfg(target_os = "windows")]
fn get_computer_name() -> Option<String> {
    use windows::Win32::System::SystemInformation::GetComputerNameW;
    
    let mut buffer = vec![0u16; 256];
    let mut size = buffer.len() as u32;
    
    unsafe {
        GetComputerNameW(Some(&mut buffer), &mut size).ok()?;
    }
    
    String::from_utf16(&buffer[..size as usize]).ok()
}

#[cfg(target_os = "windows")]
fn get_cpu_info() -> Option<u32> {
    use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    
    let mut info = SYSTEM_INFO::default();
    unsafe {
        GetSystemInfo(&mut info);
    }
    Some(unsafe { info.Anonymous.Anonymous.dwProcessorType })
}

/// 清除缓存的密钥
pub fn clear_key() {
    // 注意：OnceLock 不支持清除，这里仅作为接口
    // 实际使用中密钥会在进程结束时自动清除
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_derivation() {
        let key1 = get_encryption_key();
        let key2 = get_encryption_key();
        
        // 同一进程中应该返回相同的密钥
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }
}
