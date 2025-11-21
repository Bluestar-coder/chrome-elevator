// 构建脚本 - 编译 C/ASM 代码并链接
use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();
    
    println!("cargo:rerun-if-changed=native/");
    
    // 只在 Windows 目标时编译原生代码
    if target.contains("windows") {
        println!("cargo:warning=Building for Windows target: {}", target);
        
        // TODO: 编译 C/ASM 代码
        // 当前阶段先跳过，等待原生代码迁移
        
        // compile_native_code(&target);
    } else {
        println!("cargo:warning=Non-Windows target, skipping native code compilation");
    }
}

#[allow(dead_code)]
fn compile_native_code(target: &str) {
    let mut build = cc::Build::new();
    
    // 基本配置
    build
        .warnings(false)
        .opt_level(2);
    
    // 添加 C 源文件
    if std::path::Path::new("native/reflective_loader.c").exists() {
        build.file("native/reflective_loader.c");
    }
    
    if std::path::Path::new("native/syscalls.c").exists() {
        build.file("native/syscalls.c");
    }
    
    // 根据架构选择汇编文件
    if target.contains("x86_64") {
        if std::path::Path::new("native/syscall_trampoline_x64.asm").exists() {
            // MSVC 汇编需要特殊处理
            println!("cargo:warning=x64 assembly file found, may need manual linking");
        }
    } else if target.contains("aarch64") {
        if std::path::Path::new("native/syscall_trampoline_arm64.asm").exists() {
            println!("cargo:warning=ARM64 assembly file found, may need manual linking");
        }
    }
    
    build.compile("native");
    
    println!("cargo:rustc-link-lib=static=native");
}
