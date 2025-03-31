use super::{ProcessError, ProcessInfo, ProcessStatus, Result};
use crate::utils::app_util::get_work_dir;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};
use crate::utils::proxy_util::disable_system_proxy;
use crate::app::constants::{paths, process, messages};

pub struct ProcessManager {
    process_info: Arc<RwLock<ProcessInfo>>,
    child_process: Arc<RwLock<Option<tokio::process::Child>>>,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            process_info: Arc::new(RwLock::new(ProcessInfo {
                pid: None,
                status: ProcessStatus::Stopped,
                last_error: None,
            })),
            child_process: Arc::new(RwLock::new(None)),
        }
    }

    // 获取进程状态
    pub async fn get_status(&self) -> ProcessInfo {
        self.process_info.read().await.clone()
    }

    // 检查是否存在其他 sing-box 进程
    #[allow(dead_code)]
    async fn check_other_sing_box_process(&self) -> Option<u32> {
        // 获取自己的PID以排除
        let self_pid = {
            let info = self.process_info.read().await;
            info.pid
        };
        
        #[cfg(target_os = "windows")]
        {
            match std::process::Command::new("tasklist")
                .arg("/FI")
                .arg("IMAGENAME eq sing-box.exe")
                .arg("/FO")
                .arg("CSV")
                .arg("/NH")
                .creation_flags(process::CREATE_NO_WINDOW)
                .output()
            {
                Ok(output) => {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    if output_str.trim().is_empty() {
                        return None; // 没有sing-box进程
                    }
                    
                    // 解析所有sing-box进程的PID
                    for line in output_str.lines() {
                        let parts: Vec<&str> = line.split(',').collect();
                        if parts.len() >= 2 {
                            // 提取PID并转换为u32
                            if let Ok(pid) = parts[1].trim_matches('"').parse::<u32>() {
                                // 排除自己的PID
                                if self_pid != Some(pid) {
                                    info!("发现其他sing-box进程: PID={}", pid);
                                    return Some(pid);
                                }
                            }
                        }
                    }
                    None
                }
                Err(e) => {
                    error!("检查其他sing-box进程失败: {}", e);
                    None
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            match std::process::Command::new("pgrep")
                .arg("sing-box")
                .output()
            {
                Ok(output) => {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    if output_str.trim().is_empty() {
                        return None; // 没有sing-box进程
                    }
                    
                    // 解析所有sing-box进程的PID
                    for line in output_str.lines() {
                        if let Ok(pid) = line.trim().parse::<u32>() {
                            // 排除自己的PID
                            if self_pid != Some(pid) {
                                info!("发现其他sing-box进程: PID={}", pid);
                                return Some(pid);
                            }
                        }
                    }
                    None
                }
                Err(e) => {
                    error!("检查其他sing-box进程失败: {}", e);
                    None
                }
            }
        }
    }

    // 重置进程状态
    async fn reset_process_state(&self) {
        let mut info = self.process_info.write().await;
        info.status = ProcessStatus::Stopped;
        info.pid = None;
        info.last_error = None;

        let mut process = self.child_process.write().await;
        *process = None;
    }

    // 检查进程是否在运行
    pub async fn is_running(&self) -> bool {
        self._is_running(false).await
    }

    // 启动前检查
    async fn pre_start_check(&self) -> Result<()> {
        // 强制检查进程状态，确保状态与实际一致
        let force_check = true;
        let is_running = self._is_running(force_check).await;
        
        // 打印工作目录和内核路径的详细信息
        let work_dir = get_work_dir();
        let kernel_path = paths::get_kernel_path();
        let config_path = paths::get_config_path();
        
        info!("启动前检查 - 工作目录: {}", work_dir);
        info!("启动前检查 - 内核路径: {}", kernel_path.display());
        info!("启动前检查 - 配置文件路径: {}", config_path.display());
        
        // 检查文件是否存在
        if !kernel_path.exists() {
            error!("内核文件不存在，请先下载内核");
            return Err(ProcessError::ConfigError("内核文件不存在，请先下载内核".to_string()));
        }
        
        // 如果当前实例的进程在运行，先尝试停止它
        if is_running {
            info!("检测到应用内核已运行，尝试强制停止");
            match self.force_stop().await {
                Ok(_) => info!("成功停止当前运行的内核"),
                Err(e) => {
                    warn!("无法停止当前运行的内核: {}", e);
                    // 即使当前无法停止，仍然继续尝试下一步
                }
            }
            
            // 重置状态，以确保干净的启动环境
            self.reset_process_state().await;
        }

        #[cfg(target_os = "windows")]
        {
            // 检查是否有其他sing-box进程在运行（通过进程名称匹配）
            if self.is_process_running_by_name("sing-box.exe").await {
                info!("检测到其他sing-box进程正在运行，尝试强制停止所有实例");
                if let Err(e) = self.kill_process_by_name("sing-box.exe").await {
                    warn!("无法停止部分sing-box进程: {}", e);
                }
                
                // 等待进程完全停止
                sleep(Duration::from_secs(1)).await;
                
                // 再次检查进程是否已全部停止
                if self.is_process_running_by_name("sing-box.exe").await {
                    warn!("仍有sing-box进程在运行，将继续尝试启动");
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // 检查是否有其他sing-box进程在运行
            if self.is_process_running_by_name("sing-box").await {
                info!("检测到其他sing-box进程正在运行，尝试强制停止");
                
                // 确认进程确实存在再尝试终止
                if let Err(e) = self.kill_process_by_name("sing-box").await {
                    warn!("无法停止sing-box进程: {}", e);
                } else {
                    info!("已成功停止sing-box进程");
                }
                
                // 等待进程完全停止
                sleep(Duration::from_secs(1)).await;
                
                // 再次检查进程是否已停止
                if self.is_process_running_by_name("sing-box").await {
                    // 尝试第二次使用更激进的方式停止
                    warn!("sing-box进程仍在运行，尝试使用更直接的方式停止");
                    std::process::Command::new("killall")
                        .arg("-9")
                        .arg("sing-box")
                        .output()
                        .ok();
                    
                    sleep(Duration::from_millis(500)).await;
                    
                    if self.is_process_running_by_name("sing-box").await {
                        warn!("仍无法停止sing-box进程，将继续尝试启动");
                    }
                }
            } else {
                info!("未检测到其他sing-box进程在运行");
            }
        }

        // 检查配置文件
        self.check_config().await?;

        Ok(())
    }

    // 通过进程名称检查进程是否在运行
    async fn is_process_running_by_name(&self, process_name: &str) -> bool {
        #[cfg(target_os = "windows")]
        {
            let query = format!("IMAGENAME eq {}", process_name);
            
            match std::process::Command::new("tasklist")
                .arg("/FI")
                .arg(query)
                .arg("/FO")
                .arg("CSV")
                .arg("/NH")
                .creation_flags(process::CREATE_NO_WINDOW)
                .output()
            {
                Ok(output) => {
                    let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    !output_str.is_empty() && output_str.contains(process_name)
                }
                Err(e) => {
                    error!("检查进程名称失败: {}", e);
                    false
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // Linux中使用pgrep检查进程，使用-x参数确保完全匹配
            let process_name = process_name.replace(".exe", ""); // 移除.exe后缀
            
            // 首先检查当前程序的PID
            let self_pid = std::process::id();
            
            // 获取可能的sing-box进程，但排除自身的PID
            match std::process::Command::new("pgrep")
                .arg("-x") // 精确匹配整个进程名
                .arg(&process_name)
                .output()
            {
                Ok(output) => {
                    let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if output_str.is_empty() {
                        return false;
                    }
                    
                    // 检查返回的PID是否包含不是自身的进程
                    for line in output_str.lines() {
                        if let Ok(pid) = line.trim().parse::<u32>() {
                            if pid != self_pid {
                                info!("发现sing-box进程: PID={}, 当前进程: {}", pid, self_pid);
                                return true;
                            }
                        }
                    }
                    false
                }
                Err(e) => {
                    error!("检查进程名称失败: {}", e);
                    // 忽略pgrep可能不存在的情况
                    if e.kind() == std::io::ErrorKind::NotFound {
                        // 如果pgrep命令不存在，使用ps命令替代检查
                        match std::process::Command::new("ps")
                            .arg("-e")
                            .arg("-o")
                            .arg("comm")
                            .output()
                        {
                            Ok(ps_output) => {
                                let ps_str = String::from_utf8_lossy(&ps_output.stdout);
                                ps_str.lines().any(|line| line.trim() == process_name)
                            }
                            Err(_) => false
                        }
                    } else {
                        false
                    }
                }
            }
        }
    }

    // 通过进程名称终止所有匹配的进程
    async fn kill_process_by_name(&self, process_name: &str) -> std::io::Result<()> {
        #[cfg(target_os = "windows")]
        {
            // 使用taskkill /IM 命令强制终止所有匹配的进程
            let output = std::process::Command::new("taskkill")
                .arg("/F") // 强制终止
                .arg("/IM")
                .arg(process_name)
                .creation_flags(process::CREATE_NO_WINDOW)
                .output()?;
            
            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                if error.contains("没有运行的任务") {
                    // 忽略"没有运行的任务"错误，这意味着没有找到匹配的进程
                    return Ok(());
                }
                error!("终止进程失败: {}", error);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    format!("终止进程失败: {}", error)
                ));
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // Linux中使用精确匹配pkill命令终止进程
            let process_name = process_name.replace(".exe", ""); // 移除.exe后缀
            let self_pid = std::process::id();
            
            // 首先获取所有匹配进程的PID
            let pids = match std::process::Command::new("pgrep")
                .arg("-x") // 精确匹配进程名
                .arg(&process_name)
                .output()
            {
                Ok(output) => {
                    let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if output_str.is_empty() {
                        return Ok(()); // 没有找到进程
                    }
                    
                    // 收集所有非自身的PID
                    output_str.lines()
                        .filter_map(|line| line.trim().parse::<u32>().ok())
                        .filter(|&pid| pid != self_pid)
                        .collect::<Vec<u32>>()
                },
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        Vec::new() // pgrep不存在，返回空列表
                    } else {
                        error!("获取进程PID失败: {}", e);
                        return Err(e);
                    }
                }
            };
            
            if pids.is_empty() {
                info!("未找到需要终止的进程");
                return Ok(());
            }
            
            // 针对每个匹配的PID单独发送SIGKILL信号
            for pid in pids {
                info!("正在终止进程 PID={}", pid);
                if let Err(e) = std::process::Command::new("kill")
                    .arg("-9") // SIGKILL信号
                    .arg(pid.to_string())
                    .output()
                {
                    error!("终止进程 {} 失败: {}", pid, e);
                    // 继续尝试终止其他进程，不立即返回错误
                }
            }
        }
        
        info!("已终止所有 {} 进程", process_name);
        Ok(())
    }

    // 检查配置文件
    async fn check_config(&self) -> Result<()> {
        info!("当前工作目录: {}", get_work_dir());
        
        // 检查配置文件是否存在
        let config_path = paths::get_config_path();
        if !config_path.exists() {
            #[cfg(target_os = "linux")]
            {
                info!("配置文件不存在，尝试创建默认配置文件");
                
                // 简单的默认配置
                let default_config = r#"{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "::",
      "listen_port": 12080
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "rules": [
      {
        "geosite": "category-ads-all",
        "outbound": "block"
      }
    ],
    "final": "direct"
  }
}"#;
                
                // 确保sing-box目录存在
                if let Some(parent) = config_path.parent() {
                    if !parent.exists() {
                        info!("创建sing-box目录: {}", parent.display());
                        std::fs::create_dir_all(parent)
                            .map_err(|e| ProcessError::ConfigError(format!("创建sing-box目录失败: {}", e)))?;
                    }
                }
                
                // 写入默认配置
                match std::fs::write(&config_path, default_config) {
                    Ok(_) => info!("已创建默认配置文件"),
                    Err(e) => return Err(ProcessError::ConfigError(format!("创建配置文件失败: {}", e)))
                }
            }
            
            #[cfg(target_os = "windows")]
            {
                return Err(ProcessError::ConfigError(messages::ERR_CONFIG_READ_FAILED.to_string()));
            }
        }

        // 验证配置文件
        let config_str = std::fs::read_to_string(&config_path)
            .map_err(|e| ProcessError::ConfigError(format!("{}: {}", messages::ERR_CONFIG_READ_FAILED, e)))?;

        // 解析JSON
        let json_result: serde_json::Result<serde_json::Value> = serde_json::from_str(&config_str);
        if let Err(e) = json_result {
            return Err(ProcessError::ConfigError(format!("配置文件JSON格式错误: {}", e)));
        }

        // 验证配置有效性 - 使用sing-box自带的验证功能
        let kernel_path = paths::get_kernel_path();
        
        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new(&kernel_path)
                .arg("check")
                .arg("-c")
                .arg(&config_path)
                .creation_flags(process::CREATE_NO_WINDOW)
                .output()
                .map_err(|e| ProcessError::ConfigError(format!("无法验证配置: {}", e)))?;

            if !output.status.success() {
                let error_output = String::from_utf8_lossy(&output.stderr);
                return Err(ProcessError::ConfigError(format!("配置无效: {}", error_output)));
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            let output = std::process::Command::new(&kernel_path)
                .arg("check")
                .arg("-c")
                .arg(&config_path)
                .output()
                .map_err(|e| ProcessError::ConfigError(format!("无法验证配置: {}", e)))?;

            if !output.status.success() {
                let error_output = String::from_utf8_lossy(&output.stderr);
                return Err(ProcessError::ConfigError(format!("配置无效: {}", error_output)));
            }
        }

        info!("配置文件检查通过");
        
        // 如果输出为空，则配置有效
        Ok(())
    }

    // 启动进程
    pub async fn start(&self) -> Result<()> {
        // 保存当前状态
        let old_status = {
            let info = self.process_info.read().await;
            info.status.clone()
        };
        
        // 更新状态为启动中
        {
            let mut info = self.process_info.write().await;
            info.status = ProcessStatus::Starting;
        }
        
        // 执行启动前检查
        if let Err(e) = self.pre_start_check().await {
            self.handle_error(e).await?;
            return Err(ProcessError::StartFailed("启动前检查失败".to_string()));
        }
        
        // 获取内核路径和配置路径
        let kernel_path = paths::get_kernel_path();
        let config_path = paths::get_config_path();
        let work_dir = paths::get_kernel_work_dir();
        
        info!("内核路径: {:?}", kernel_path);
        info!("配置路径: {:?}", config_path);
        info!("工作目录: {:?}", work_dir);
        
        // 构建命令
        let mut cmd = Command::new(&kernel_path);
        cmd.arg("run");
        cmd.arg("--config");
        cmd.arg(&config_path);
        cmd.current_dir(&work_dir);
        
        // 添加平台特定的设置
        #[cfg(target_os = "windows")]
        {
            // 在Windows上隐藏控制台窗口
            let mut command_ext = cmd.creation_flags(process::CREATE_NO_WINDOW);
            
            // 启动进程
            match command_ext.spawn() {
                Ok(child) => {
                    // 保存子进程信息
                    let pid = child.id().map(|id| id as u32);
                    
                    // 更新进程状态
                    {
                        let mut info = self.process_info.write().await;
                        info.pid = pid;
                        info.status = ProcessStatus::Running;
                    }
                    
                    // 保存子进程引用
                    {
                        let mut child_process = self.child_process.write().await;
                        *child_process = Some(child);
                    }
                    
                    info!("进程已启动, PID: {:?}", pid);
                }
                Err(e) => {
                    error!("进程启动失败: {}", e);
                    
                    // 恢复原状态
                    {
                        let mut info = self.process_info.write().await;
                        info.status = old_status;
                    }
                    
                    return Err(ProcessError::StartFailed(e.to_string()));
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // 启动进程
            match cmd.spawn() {
                Ok(child) => {
                    // 保存子进程信息
                    let pid = child.id().map(|id| id as u32);
                    
                    // 更新进程状态
                    {
                        let mut info = self.process_info.write().await;
                        info.pid = pid;
                        info.status = ProcessStatus::Running;
                    }
                    
                    // 保存子进程引用
                    {
                        let mut child_process = self.child_process.write().await;
                        *child_process = Some(child);
                    }
                    
                    info!("进程已启动, PID: {:?}", pid);
                }
                Err(e) => {
                    error!("进程启动失败: {}", e);
                    
                    // 恢复原状态
                    {
                        let mut info = self.process_info.write().await;
                        info.status = old_status;
                    }
                    
                    return Err(ProcessError::StartFailed(e.to_string()));
                }
            }
        }
        
        info!("{}", messages::INFO_PROCESS_STARTED);
        Ok(())
    }

    // 停止进程
    pub async fn stop(&self) -> Result<()> {
        // 检查进程状态
        let status = self.get_status().await.status;
        if matches!(status, ProcessStatus::Stopped) {
            return Ok(());
        }

        // 更新状态为停止中
        {
            let mut info = self.process_info.write().await;
            info.status = ProcessStatus::Stopping;
        }

        // 首先尝试优雅地停止进程
        let stop_result = self.graceful_stop().await;
        
        // 如果优雅停止失败，则强制终止
        if stop_result.is_err() {
            warn!("进程停止超时，尝试强制终止");
            self.force_stop().await?;
        }
        
        // 关闭系统代理
        if let Err(e) = disable_system_proxy() {
            warn!("关闭系统代理失败: {}", e);
        } else {
            info!("{}", messages::INFO_SYSTEM_PROXY_DISABLED);
        }

        // 更新进程状态
        {
            let mut info = self.process_info.write().await;
            info.status = ProcessStatus::Stopped;
            info.pid = None;
        }

        info!("{}", messages::INFO_PROCESS_STOPPED);
        Ok(())
    }

    // 发送停止信号
    #[allow(dead_code)]
    fn send_signal(&self, pid: u32) -> std::io::Result<()> {
        #[cfg(target_os = "windows")]
        {
            std::process::Command::new("taskkill")
                .arg("/PID")
                .arg(pid.to_string())
                .creation_flags(process::CREATE_NO_WINDOW)
                .output()?;
        }
        
        #[cfg(target_os = "linux")]
        {
            // Linux中使用kill命令发送SIGTERM信号
            std::process::Command::new("kill")
                .arg(pid.to_string())
                .output()?;
        }
        
        Ok(())
    }

    // 强制结束进程
    fn kill_process(&self, pid: u32) -> std::io::Result<()> {
        #[cfg(target_os = "windows")]
        {
            std::process::Command::new("taskkill")
                .arg("/F")
                .arg("/PID")
                .arg(pid.to_string())
                .creation_flags(process::CREATE_NO_WINDOW)
                .output()?;
        }
        
        #[cfg(target_os = "linux")]
        {
            // 首先尝试发送SIGTERM（15）信号，这是更优雅的终止方式
            info!("尝试使用SIGTERM终止进程 PID={}", pid);
            let term_result = std::process::Command::new("kill")
                .arg("-15")  // SIGTERM信号
                .arg(pid.to_string())
                .output();
                
            if let Err(e) = &term_result {
                warn!("SIGTERM信号发送失败: {}", e);
            } else if let Ok(output) = &term_result {
                if !output.status.success() {
                    let error = String::from_utf8_lossy(&output.stderr);
                    warn!("SIGTERM发送可能失败: {}", error);
                } else {
                    info!("已发送SIGTERM信号");
                    
                    // 给进程一些时间响应SIGTERM
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    
                    // 检查进程是否已经终止
                    let check_cmd = std::process::Command::new("kill")
                        .arg("-0")  // 检查进程是否存在
                        .arg(pid.to_string())
                        .output();
                        
                    if let Ok(check) = check_cmd {
                        if !check.status.success() {
                            // 进程已经响应SIGTERM并终止
                            info!("进程已响应SIGTERM并终止");
                            return Ok(());
                        }
                    }
                }
            }
            
            // 如果SIGTERM不成功，再使用SIGKILL（9）信号
            info!("尝试使用SIGKILL终止进程 PID={}", pid);
            let kill_result = std::process::Command::new("kill")
                .arg("-9")  // SIGKILL信号
                .arg(pid.to_string())
                .output();
                
            // 额外记录SIGKILL的结果
            if let Err(e) = &kill_result {
                warn!("SIGKILL信号发送失败: {}", e);
            } else if let Ok(output) = &kill_result {
                if !output.status.success() {
                    let error = String::from_utf8_lossy(&output.stderr);
                    warn!("SIGKILL发送可能失败: {}", error);
                } else {
                    info!("已发送SIGKILL信号");
                }
            }
            
            // 返回SIGKILL的结果
            kill_result?;
        }
        
        Ok(())
    }

    // 重启进程 强制停止
    pub async fn restart(&self) -> Result<()> {
        self.stop().await?;
        // 休眠1s
        sleep(Duration::from_secs(1)).await;
        self.start().await?;
        Ok(())
    }

    // 错误处理
    async fn handle_error(&self, err: ProcessError) -> Result<()> {
        let mut info = self.process_info.write().await;
        info.status = ProcessStatus::Failed(err.to_string());
        info.last_error = Some(err.to_string());
        error!("进程错误: {}", err);
        Ok(())
    }

    // 优雅停止进程
    #[allow(dead_code)]
    async fn graceful_stop(&self) -> Result<()> {
        let pid = {
            let info = self.process_info.read().await;
            info.pid.ok_or(ProcessError::NotRunning)?
        };

        // 尝试发送正常停止信号
        if let Err(e) = self.send_signal(pid) {
            return Err(ProcessError::StopFailed(format!("发送停止信号失败: {}", e)));
        }

        // 等待进程停止的超时时间
        let timeout = Duration::from_secs(process::GRACEFUL_TIMEOUT);
        let start = std::time::Instant::now();

        // 等待进程停止
        while self.check_process_exists(Some(pid)).await {
            if start.elapsed() > timeout {
                return Err(ProcessError::StopFailed("进程停止超时".to_string()));
            }
            sleep(Duration::from_millis(100)).await;
        }

        Ok(())
    }

    // 强制停止进程
    async fn force_stop(&self) -> Result<()> {
        let pid = {
            let info = self.process_info.read().await;
            info.pid.ok_or(ProcessError::NotRunning)?
        };

        info!("正在强制停止进程，PID={}", pid);

        // 强制结束进程
        if let Err(e) = self.kill_process(pid) {
            warn!("第一次尝试停止进程失败: {}", e);
            
            // 给进程一些时间响应第一次终止尝试
            sleep(Duration::from_millis(300)).await;
            
            // 再次检查进程是否存在
            if !self.check_process_exists(Some(pid)).await {
                info!("进程已经停止");
                return Ok(());
            }
            
            // 如果进程还在运行，尝试使用不同的方法
            #[cfg(target_os = "linux")]
            {
                info!("尝试使用更强力的方法停止进程");
                
                // 尝试直接使用killall命令
                if let Err(e) = std::process::Command::new("killall")
                    .arg("-9")  // SIGKILL信号
                    .arg("sing-box")
                    .output() 
                {
                    warn!("使用killall停止进程失败: {}", e);
                } else {
                    info!("已发送killall命令");
                }
                
                // 尝试使用pkill命令
                if let Err(e) = std::process::Command::new("pkill")
                    .arg("-9")  // SIGKILL信号
                    .arg("-x")  // 精确匹配
                    .arg("sing-box")
                    .output()
                {
                    warn!("使用pkill停止进程失败: {}", e);
                } else {
                    info!("已发送pkill命令");
                }
                
                // 使用更直接的系统调用发送SIGKILL信号
                unsafe {
                    let ret = libc::kill(pid as i32, libc::SIGKILL);
                    if ret != 0 {
                        let err = std::io::Error::last_os_error();
                        warn!("直接发送SIGKILL失败: {}", err);
                    } else {
                        info!("已直接发送SIGKILL信号");
                    }
                }
            }
            
            // 给进程更多时间完全终止
            sleep(Duration::from_millis(500)).await;
        } else {
            info!("已发送终止信号到进程 PID={}", pid);
            // 等待进程终止
            sleep(Duration::from_millis(500)).await;
        }
        
        // 再次检查进程是否仍存在
        let retries = 3;
        for i in 0..retries {
            if !self.check_process_exists(Some(pid)).await {
                info!("确认进程已终止");
                return Ok(());
            }
            
            if i < retries - 1 {
                warn!("进程仍在运行，等待额外时间 (尝试 {}/{})", i+1, retries);
                sleep(Duration::from_millis(300)).await;
            }
        }
        
        if self.check_process_exists(Some(pid)).await {
            error!("无法终止进程，PID={}，所有方法均已尝试", pid);
            return Err(ProcessError::StopFailed("无法强制停止进程，尝试多种方法后进程仍在运行".to_string()));
        }

        Ok(())
    }

    // 检查进程是否存在
    async fn check_process_exists(&self, pid: Option<u32>) -> bool {
        if let Some(pid) = pid {
            #[cfg(target_os = "windows")]
            {
                // 使用具体的PID格式化查询，确保准确匹配
                let query = format!("PID eq {}", pid);
                
                match std::process::Command::new("tasklist")
                    .arg("/FI")
                    .arg(query)
                    .arg("/FO")
                    .arg("CSV")
                    .arg("/NH") // 不显示标题行
                    .creation_flags(process::CREATE_NO_WINDOW)
                    .output()
                {
                    Ok(output) => {
                        let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        // 检查输出是否包含PID
                        // 输出格式应该是 "sing-box.exe","PID",...
                        if output_str.is_empty() {
                            return false;
                        }
                        
                        // 更严格地检查PID是否匹配
                        output_str.contains(&format!(",\"{}\"", pid))
                    }
                    Err(_) => {
                        error!("查询进程状态失败");
                        false
                    }
                }
            }
            
            #[cfg(target_os = "linux")]
            {
                // 方法1: 直接检查/proc/{pid}目录是否存在（最可靠）
                let pid_path = std::path::Path::new("/proc").join(pid.to_string());
                if !pid_path.exists() {
                    return false; // 进程不存在
                }
                
                // 进一步验证这是否是sing-box进程
                // 尝试多种方法检查进程身份
                
                // 方法1a: 检查/proc/{pid}/comm文件
                let comm_path = pid_path.join("comm");
                if comm_path.exists() {
                    if let Ok(comm_content) = std::fs::read_to_string(&comm_path) {
                        let comm = comm_content.trim();
                        if comm == "sing-box" {
                            info!("通过/proc/{}/comm确认进程存在", pid);
                            return true;
                        }
                    }
                }
                
                // 方法1b: 检查/proc/{pid}/cmdline文件
                let cmd_path = pid_path.join("cmdline");
                if cmd_path.exists() {
                    if let Ok(cmd_content) = std::fs::read_to_string(&cmd_path) {
                        if cmd_content.contains("sing-box") {
                            info!("通过/proc/{}/cmdline确认进程存在", pid);
                            return true;
                        }
                    }
                }
                
                // 方法1c: 检查/proc/{pid}/exe符号链接
                let exe_path = pid_path.join("exe");
                if exe_path.exists() {
                    if let Ok(target) = std::fs::read_link(&exe_path) {
                        let target_str = target.to_string_lossy();
                        if target_str.contains("sing-box") {
                            info!("通过/proc/{}/exe确认进程存在", pid);
                            return true;
                        }
                    }
                }
                
                // 方法2: 使用ps命令检查进程名
                match std::process::Command::new("ps")
                    .arg("-p")
                    .arg(pid.to_string())
                    .arg("-o")
                    .arg("comm=") // 只显示命令名
                    .output()
                {
                    Ok(output) => {
                        let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if !output_str.is_empty() {
                            if output_str == "sing-box" {
                                info!("通过ps命令确认进程存在 (PID={})", pid);
                                return true;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("使用ps检查进程失败: {}", e);
                    }
                }
                
                // 方法3: 使用kill -0检查进程是否存在
                match std::process::Command::new("kill")
                    .arg("-0")
                    .arg(pid.to_string())
                    .output()
                {
                    Ok(output) => {
                        if output.status.success() {
                            // PID存在，但我们不能确定它是sing-box
                            // 在这里，我们可以决定将其视为不是sing-box进程
                            info!("找到PID={}的进程，但无法确认是否为sing-box", pid);
                            return false;
                        }
                    }
                    Err(e) => {
                        warn!("使用kill -0检查进程存在失败: {}", e);
                    }
                }
                
                // 找不到确定的sing-box进程
                false
            }
        } else {
            false
        }
    }

    // 内部是否运行中检查函数，可以强制检查实际进程
    async fn _is_running(&self, force_check: bool) -> bool {
        // 首先检查进程信息
        let info = self.process_info.read().await;
        let status_running = matches!(
            info.status,
            ProcessStatus::Running | ProcessStatus::Starting
        );

        // 如果状态显示为非运行，且不强制检查，直接返回false
        if !status_running && !force_check {
            return false;
        }

        // 如果没有PID，说明进程未运行
        if info.pid.is_none() {
            if status_running {
                // 状态不一致，需要重置
                drop(info); // 释放读锁
                self.reset_process_state().await;
                warn!("进程状态显示运行中，但没有PID，已重置状态");
            }
            return false;
        }

        // 检查进程是否实际存在
        let pid = info.pid.unwrap(); // 安全，因为已经检查了is_none
        let exists = self.check_process_exists(Some(pid)).await;
        
        if !exists && status_running {
            // 进程不存在但状态显示运行中，重置状态
            drop(info); // 释放读锁
            self.reset_process_state().await;
            warn!("进程状态显示运行中 (PID: {})，但实际进程不存在，已重置状态", pid);
            return false;
        }

        // 返回实际进程存在状态
        exists
    }
}

