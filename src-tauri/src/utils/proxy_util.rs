use std::io;
#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;
#[cfg(target_os = "windows")]
use crate::app::constants::registry;
use tracing::info;
use std::process::Command;
use std::fs;
use std::path::Path;

pub fn disable_system_proxy() -> io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let settings = hkcu.open_subkey_with_flags(registry::INTERNET_SETTINGS, KEY_WRITE)?;

        // 禁用代理
        settings.set_value(registry::PROXY_ENABLE, &0u32)?;

        // 清空代理服务器地址
        settings.set_value(registry::PROXY_SERVER, &"")?;

        // 通知系统代理设置已更改
        unsafe {
            winapi::um::wininet::InternetSetOptionW(
                std::ptr::null_mut(),
                winapi::um::wininet::INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null_mut(),
                0,
            );
            winapi::um::wininet::InternetSetOptionW(
                std::ptr::null_mut(),
                winapi::um::wininet::INTERNET_OPTION_REFRESH,
                std::ptr::null_mut(),
                0,
            );
        }
    }

    #[cfg(target_os = "linux")]
    {
        // 在Linux上，我们尝试多种桌面环境的代理设置方式
        
        // 1. GNOME/Unity桌面环境
        let _ = Command::new("gsettings")
            .args(&["set", "org.gnome.system.proxy", "mode", "none"])
            .output();
        
        // 2. KDE桌面环境
        if Path::new("/usr/bin/kwriteconfig5").exists() {
            let _ = Command::new("kwriteconfig5")
                .args(&["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0"])
                .output();
        }
        
        // 3. 环境变量方法 - 清除用户配置文件中的代理设置
        let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/home"));
        let bashrc_path = format!("{}/.bashrc", home);
        let zshrc_path = format!("{}/.zshrc", home);
        
        // 尝试移除.bashrc中的代理设置
        if Path::new(&bashrc_path).exists() {
            if let Ok(content) = fs::read_to_string(&bashrc_path) {
                let new_content = remove_proxy_from_content(content);
                let _ = fs::write(&bashrc_path, new_content);
            }
        }
        
        // 尝试移除.zshrc中的代理设置
        if Path::new(&zshrc_path).exists() {
            if let Ok(content) = fs::read_to_string(&zshrc_path) {
                let new_content = remove_proxy_from_content(content);
                let _ = fs::write(&zshrc_path, new_content);
            }
        }
        
        info!("已尝试禁用系统代理");
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_proxy_from_content(content: String) -> String {
    // 移除代理相关的行
    content.lines()
        .filter(|line| {
            !line.contains("http_proxy=") && 
            !line.contains("https_proxy=") &&
            !line.contains("all_proxy=") &&
            !line.contains("HTTP_PROXY=") &&
            !line.contains("HTTPS_PROXY=") &&
            !line.contains("ALL_PROXY=") &&
            !line.contains("export http_proxy") &&
            !line.contains("export https_proxy") &&
            !line.contains("export all_proxy") &&
            !line.contains("export HTTP_PROXY") &&
            !line.contains("export HTTPS_PROXY") &&
            !line.contains("export ALL_PROXY")
        })
        .collect::<Vec<&str>>()
        .join("\n")
}
