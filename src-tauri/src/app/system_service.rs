use crate::app::constants::messages;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::process::Command;

// 以管理员权限重启
#[tauri::command]
pub fn restart_as_admin() -> Result<(), String> {
    let current_exe =
        std::env::current_exe().map_err(|e| format!("{}: {}", messages::ERR_GET_EXE_PATH_FAILED, e))?;

    #[cfg(target_os = "windows")]
    {
        let result = std::process::Command::new("powershell")
            .arg("Start-Process")
            .arg(current_exe.to_str().unwrap())
            .arg("-Verb")
            .arg("RunAs")
            .creation_flags(process::CREATE_NO_WINDOW)
            .spawn();

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{}: {}", messages::ERR_RESTART_FAILED, e)),
        }
    }

    #[cfg(target_os = "linux")]
    {
        let result = std::process::Command::new("pkexec")
            .arg(current_exe.to_str().unwrap())
            .spawn();

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{}: {}", messages::ERR_RESTART_FAILED, e)),
        }
    }
}

// 检查是否有管理员权限
#[tauri::command]
pub fn check_admin() -> bool {
    #[cfg(target_os = "windows")]
    {
        let result = std::process::Command::new("net")
            .arg("session")
            .creation_flags(process::CREATE_NO_WINDOW)
            .output();

        match result {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Linux中检查是否有root权限
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            return true;
        }

        // 尝试使用sudo -n检查是否可以无密码使用sudo
        match Command::new("sudo")
            .arg("-n")
            .arg("true")
            .output()
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }
} 