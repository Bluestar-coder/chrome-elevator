// 进程操作模块 - 创建、管理和注入目标进程

use anyhow::Result;
use std::ffi::c_void;
use std::mem;
use std::ptr;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::*;

/// 目标进程句柄和信息
pub struct TargetProcess {
    pub process_handle: HANDLE,
    pub process_id: u32,
    pub thread_handle: HANDLE,
}

impl TargetProcess {
    /// 以暂停状态创建新进程
    pub fn create_suspended(exe_path: &str) -> Result<Self> {
        // 转换路径为宽字符
        let wide_path: Vec<u16> = exe_path.encode_utf16().chain(std::iter::once(0)).collect();

        let mut startup_info: STARTUPINFOW = unsafe { mem::zeroed() };
        startup_info.cb = mem::size_of::<STARTUPINFOW>() as u32;

        let mut process_info: PROCESS_INFORMATION = unsafe { mem::zeroed() };

        unsafe {
            CreateProcessW(
                PCWSTR(wide_path.as_ptr()),
                PWSTR(ptr::null_mut()),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                None,
                &startup_info,
                &mut process_info,
            )?;
        }

        Ok(Self {
            process_handle: HANDLE(process_info.hProcess.0),
            process_id: process_info.dwProcessId,
            thread_handle: HANDLE(process_info.hThread.0),
        })
    }

    /// 从进程 ID 打开进程
    pub fn open(process_id: u32) -> Result<Self> {
        unsafe {
            let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id)?;

            Ok(Self {
                process_handle,
                process_id,
                thread_handle: HANDLE(0),
            })
        }
    }

    /// 获取进程 ID
    pub fn process_id(&self) -> u32 {
        self.process_id
    }

    /// 获取进程句柄
    pub fn handle(&self) -> HANDLE {
        self.process_handle
    }

    /// 恢复进程执行（启动暂停的进程）
    pub fn resume(&self) -> Result<()> {
        if self.thread_handle.is_invalid() {
            anyhow::bail!("Thread handle is invalid");
        }

        unsafe {
            let result = ResumeThread(self.thread_handle);
            if result == 0xFFFFFFFF {
                anyhow::bail!("Failed to resume thread");
            }
        }

        Ok(())
    }

    /// 等待进程退出
    pub fn wait_for_exit(&self, timeout_ms: u32) -> Result<u32> {
        unsafe {
            let result = WaitForSingleObject(self.process_handle, timeout_ms);
            match result {
                WAIT_OBJECT_0 => {
                    let mut exit_code = 0u32;
                    GetExitCodeProcess(self.process_handle, &mut exit_code)?;
                    Ok(exit_code)
                }
                WAIT_TIMEOUT => anyhow::bail!("Process wait timeout"),
                _ => anyhow::bail!("Wait failed with code {}", result.0),
            }
        }
    }

    /// 在目标进程中创建远程线程执行代码
    ///
    /// # 参数
    /// - `code_address`: 代码在目标进程中的地址
    /// - `param`: 传递给线程的参数
    ///
    /// # 返回
    /// 创建的远程线程句柄
    pub fn create_remote_thread(&self, code_address: *mut u8, param: *mut u8) -> Result<HANDLE> {
        unsafe {
            let thread_proc: extern "system" fn(*mut c_void) -> u32 =
                std::mem::transmute(code_address as *const u8);

            let thread_handle = CreateRemoteThread(
                self.process_handle,
                None,
                0,
                Some(thread_proc),
                Some(param as *mut c_void),
                0,
                None,
            )?;

            Ok(thread_handle)
        }
    }

    /// 等待远程线程完成
    pub fn wait_thread(thread_handle: HANDLE, timeout_ms: u32) -> Result<u32> {
        unsafe {
            let result = WaitForSingleObject(thread_handle, timeout_ms);
            match result {
                WAIT_OBJECT_0 => {
                    let mut exit_code = 0u32;
                    GetExitCodeThread(thread_handle, &mut exit_code)?;
                    Ok(exit_code)
                }
                WAIT_TIMEOUT => anyhow::bail!("Thread wait timeout"),
                _ => anyhow::bail!("Wait failed with code {}", result.0),
            }
        }
    }

    /// 执行完整的代码注入流程
    ///
    /// # 步骤
    /// 1. 分配内存
    /// 2. 写入代码
    /// 3. 设置为可执行
    /// 4. 创建远程线程
    /// 5. 等待执行完成
    pub fn inject_and_execute(&self, shellcode: &[u8], param: Option<&[u8]>) -> Result<u32> {
        use super::memory::MemoryManager;

        let memory_mgr = MemoryManager::new_from_handle(self.process_handle);

        // 1. 分配代码内存
        let code_buffer = memory_mgr.allocate(shellcode.len())?;

        // 2. 分配参数内存（如果有）
        let param_address = if let Some(p) = param {
            let param_buf = memory_mgr.allocate(p.len())?;
            memory_mgr.write(param_buf.address(), p)?;
            param_buf.address()
        } else {
            ptr::null_mut()
        };

        // 3. 写入代码
        memory_mgr.write(code_buffer.address(), shellcode)?;

        // 4. 设置为可执行
        memory_mgr.make_executable(code_buffer.address(), shellcode.len())?;

        // 5. 创建远程线程
        let thread_handle = self.create_remote_thread(code_buffer.address(), param_address)?;

        // 6. 等待执行完成
        let exit_code = Self::wait_thread(thread_handle, 5000)?;

        // 7. 清理
        unsafe {
            CloseHandle(thread_handle);
        }
        let _ = memory_mgr.free(code_buffer.address(), shellcode.len());
        if !param_address.is_null() {
            let _ = memory_mgr.free(param_address, param.unwrap_or(&[]).len());
        }

        Ok(exit_code)
    }

    /// 终止进程
    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        unsafe {
            TerminateProcess(self.process_handle, exit_code)?;
            Ok(())
        }
    }
}

impl Drop for TargetProcess {
    fn drop(&mut self) {
        unsafe {
            if !self.process_handle.is_invalid() {
                let _ = CloseHandle(self.process_handle);
            }
            if !self.thread_handle.is_invalid() {
                let _ = CloseHandle(self.thread_handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_struct() {
        // 测试 TargetProcess 结构的创建
        // 实际的进程创建需要在 Windows 系统上测试
        let _ = TargetProcess {
            process_handle: HANDLE(std::ptr::null_mut::<()>() as isize),
            process_id: 12345,
            thread_handle: HANDLE(std::ptr::null_mut::<()>() as isize),
        };
    }
}
