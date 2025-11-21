// 内存操作模块 - 在目标进程中进行内存分配、读写和保护

use anyhow::Result;
use windows::Win32::System::Memory::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::{WriteProcessMemory, ReadProcessMemory};
use super::process::TargetProcess;
use std::ffi::c_void;

/// 内存缓冲区
pub struct MemoryBuffer {
    address: *mut u8,
    size: usize,
}

impl MemoryBuffer {
    /// 从原始指针创建
    pub fn from_ptr(address: *mut u8, size: usize) -> Self {
        Self { address, size }
    }

    /// 获取地址
    pub fn address(&self) -> *mut u8 {
        self.address
    }

    /// 获取大小
    pub fn size(&self) -> usize {
        self.size
    }

    /// 转换为原始指针
    pub fn as_ptr(&self) -> *mut u8 {
        self.address
    }
}

/// 内存管理器
pub struct MemoryManager {
    process: TargetProcess,
}

impl MemoryManager {
    /// 创建新的内存管理器
    pub fn new(process: TargetProcess) -> Self {
        Self { process }
    }

    /// 从进程句柄创建内存管理器（用于代码注入场景）
    pub fn new_from_handle(process_handle: HANDLE) -> Self {
        // 创建临时TargetProcess用于内存操作
        let target = TargetProcess {
            process_handle,
            process_id: 0, // 未知
            thread_handle: HANDLE(0),
        };
        Self { process: target }
    }

    /// 在目标进程中分配内存（使用 Windows API）
    pub fn allocate(&self, size: usize) -> Result<MemoryBuffer> {
        unsafe {
            let result = VirtualAllocEx(
                self.process.handle(),
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if result.is_null() {
                anyhow::bail!("Failed to allocate memory in target process");
            }

            Ok(MemoryBuffer {
                address: result as *mut u8,
                size,
            })
        }
    }

    /// 向目标进程写入数据（使用 Windows API）
    pub fn write(&self, address: *mut u8, data: &[u8]) -> Result<usize> {
        unsafe {
            let mut bytes_written = 0usize;

            WriteProcessMemory(
                self.process.handle(),
                address as *const c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                Some(&mut bytes_written),
            )?;

            Ok(bytes_written)
        }
    }

    /// 从目标进程读取数据（使用 Windows API）
    pub fn read(&self, address: *const u8, size: usize) -> Result<Vec<u8>> {
        unsafe {
            let mut buffer = vec![0u8; size];
            let mut bytes_read = 0usize;

            ReadProcessMemory(
                self.process.handle(),
                address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                Some(&mut bytes_read),
            )?;

            buffer.truncate(bytes_read);
            Ok(buffer)
        }
    }

    /// 修改内存保护属性（使用 Windows API）
    pub fn protect(
        &self,
        address: *mut u8,
        size: usize,
        new_protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS> {
        unsafe {
            let mut old_protect = PAGE_NOACCESS;

            VirtualProtectEx(
                self.process.handle(),
                address as *const c_void,
                size,
                new_protect,
                &mut old_protect,
            )?;

            Ok(old_protect)
        }
    }

    /// 将内存设置为可执行 (PAGE_EXECUTE_READ)
    pub fn make_executable(&self, address: *mut u8, size: usize) -> Result<()> {
        self.protect(address, size, PAGE_EXECUTE_READ)?;
        Ok(())
    }

    /// 释放内存（高级操作）
    pub fn free(&self, address: *mut u8, _size: usize) -> Result<()> {
        unsafe {
            VirtualFreeEx(
                self.process.handle(),
                address as *mut c_void,
                0,
                MEM_RELEASE,
            )?;

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_buffer_creation() {
        let buffer = MemoryBuffer::from_ptr(0x1000 as *mut u8, 4096);
        assert_eq!(buffer.size(), 4096);
        assert!(!buffer.address().is_null());
    }
}
