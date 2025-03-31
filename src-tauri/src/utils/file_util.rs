use futures_util::StreamExt;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tracing::{error, info};
use zip::ZipArchive;
use crate::app::constants::{messages, network};
use std::process::Command;

// 根据url下载文件到指定位置
pub async fn download_file<F>(url: String, path: &str, progress_callback: F) -> Result<(), String>
where
    F: Fn(u32) + Send + 'static,
{
    let file_path = Path::new(path);
    info!("{}: {} -> {}", messages::INFO_DOWNLOAD_STARTED, url, file_path.to_str().unwrap());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(network::HTTP_TIMEOUT_SECONDS))
        .no_proxy() // 禁用代理
        .build()
        .map_err(|e| format!("{}: {}", messages::ERR_HTTP_CLIENT_FAILED, e))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("{}: {}", messages::ERR_REQUEST_FAILED, e))?;

    if !response.status().is_success() {
        return Err(format!("{}: {}", messages::ERR_SERVER_ERROR, response.status()));
    }

    // 获取文件大小，如果不存在则为0
    let total_size = response.content_length().unwrap_or(0);
    let unknown_size = total_size == 0;
    
    if unknown_size {
        info!("无法获取文件大小，将使用流式下载");
    }

    // 创建目录
    if let Some(parent) = file_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            error!("{}: {}", messages::ERR_CREATE_DIR_FAILED, e);
            return Err(format!("{}: {}", messages::ERR_CREATE_DIR_FAILED, e));
        }
    }

    // 创建临时文件
    let temp_path = file_path.with_extension("tmp");
    let mut file = File::create(&temp_path).map_err(|e| format!("{}: {}", messages::ERR_CREATE_FILE_FAILED, e))?;

    let mut downloaded = 0u64;
    let mut stream = response.bytes_stream();
    let mut last_percent = 0u32;
    let mut last_progress_update = std::time::Instant::now();

    // 开始下载
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|e| format!("{}: {}", messages::ERR_REQUEST_FAILED, e))?;
        file.write_all(&chunk)
            .map_err(|e| format!("{}: {}", messages::ERR_WRITE_FILE_FAILED, e))?;

        downloaded += chunk.len() as u64;
        
        // 根据是否知道文件大小，使用不同的进度计算方式
        if unknown_size {
            // 对于未知大小的文件，每1MB更新一次进度，使用已下载的大小作为进度指示
            // 下载的越多，进度条增长越慢，给用户一种持续下载的感觉
            let now = std::time::Instant::now();
            if now.duration_since(last_progress_update).as_millis() > 500 { // 每500ms更新一次
                let percent = ((downloaded as f64 / 1_000_000.0).min(100.0)) as u32;
                if percent != last_percent {
                    last_percent = percent;
                    progress_callback(percent);
                    last_progress_update = now;
                }
            }
        } else {
            // 已知文件大小，正常计算百分比
            let percent = ((downloaded as f64 / total_size as f64) * 100.0) as u32;
            if percent != last_percent {
                last_percent = percent;
                progress_callback(percent);
            }
        }
    }

    // 完成下载，重命名临时文件
    std::fs::rename(&temp_path, &file_path)
        .map_err(|e| format!("{}: {}", messages::ERR_WRITE_FILE_FAILED, e))?;

    Ok(())
}

pub async fn unzip_file(path: &str, to: &str) -> Result<(), String> {
    info!("{}: {} -> {}", messages::INFO_UNZIP_STARTED, path, to);

    if path.ends_with(".tar.gz") || path.ends_with(".tgz") {
        extract_tar_gz(path, to).await
    } else {
        extract_zip(path, to).await
    }
}

// 解压zip文件
async fn extract_zip(path: &str, to: &str) -> Result<(), String> {
    // 打开ZIP文件
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            error!("{}: {}", messages::ERR_OPEN_FILE_FAILED, e);
            return Err(format!("{}: {}", messages::ERR_OPEN_FILE_FAILED, e));
        }
    };

    // 创建ZipArchive对象
    let mut archive = match ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(e) => {
            error!("{}: {}", messages::ERR_READ_ARCHIVE_FAILED, e);
            return Err(format!("{}: {}", messages::ERR_READ_ARCHIVE_FAILED, e));
        }
    };

    // 确保目标目录存在
    if let Err(e) = std::fs::create_dir_all(to) {
        error!("{}: {}", messages::ERR_CREATE_DIR_FAILED, e);
        return Err(format!("{}: {}", messages::ERR_CREATE_DIR_FAILED, e));
    }

    // 遍历ZIP文件中的所有条目
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("{}: {}", messages::ERR_EXTRACT_FILE_FAILED, e))?;

        // 获取文件名，根据平台进行不同处理
        #[cfg(target_os = "windows")]
        let outpath = {
            // Windows下只提取文件名部分，忽略路径
            let file_name = match Path::new(file.name()).file_name() {
                Some(name) => name,
                None => {
                    error!("{}: {}", messages::ERR_INVALID_FILENAME, file.name());
                    continue;
                }
            };
            Path::new(to).join(file_name)
        };

        #[cfg(target_os = "linux")]
        let outpath = {
            // Linux下处理完整的文件路径，但去掉最顶层目录
            let file_path = Path::new(file.name());
            let components: Vec<_> = file_path.components().collect();
            
            // 如果路径太短，可能是顶级文件或目录
            if components.len() <= 1 {
                if let Some(file_name) = file_path.file_name() {
                    Path::new(to).join(file_name)
                } else {
                    error!("{}: {}", messages::ERR_INVALID_FILENAME, file.name());
                    continue;
                }
            } else {
                // 跳过顶层目录，保留其余路径结构
                let mut new_path = Path::new(to).to_path_buf();
                for component in components.iter().skip(1) {
                    new_path = new_path.join(component);
                }
                new_path
            }
        };

        info!("{}: {}", messages::INFO_EXTRACTING_FILE, outpath.display());

        if file.is_dir() {
            std::fs::create_dir_all(&outpath).map_err(|e| format!("{}: {}", messages::ERR_CREATE_DIR_FAILED, e))?;
        } else {
            // 创建文件父目录
            if let Some(parent) = outpath.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent).map_err(|e| format!("{}: {}", messages::ERR_CREATE_DIR_FAILED, e))?;
                }
            }
            
            // 创建文件并写入内容
            let mut outfile = File::create(&outpath).map_err(|e| format!("{}: {}", messages::ERR_CREATE_FILE_FAILED, e))?;
            std::io::copy(&mut file, &mut outfile).map_err(|e| format!("{}: {}", messages::ERR_WRITE_FILE_FAILED, e))?;
            
            // 设置Linux下的可执行权限
            #[cfg(target_os = "linux")]
            if outpath.file_name().map_or(false, |name| name == "sing-box") {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = outpath.metadata() {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o755); // rwxr-xr-x
                    if let Err(e) = std::fs::set_permissions(&outpath, perms) {
                        error!("设置可执行权限失败: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

// 解压tar.gz文件
async fn extract_tar_gz(path: &str, to: &str) -> Result<(), String> {
    info!("解压tar.gz文件: {} -> {}", path, to);
    
    // 确保目标目录存在
    if let Err(e) = std::fs::create_dir_all(to) {
        error!("{}: {}", messages::ERR_CREATE_DIR_FAILED, e);
        return Err(format!("{}: {}", messages::ERR_CREATE_DIR_FAILED, e));
    }
    
    // 使用tar命令解压（Linux系统自带）
    let output = Command::new("tar")
        .current_dir(to)
        .arg("-xzf")
        .arg(path)
        .output()
        .map_err(|e| format!("解压文件失败: {}", e))?;
    
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        error!("tar命令失败: {}", error);
        return Err(format!("tar命令失败: {}", error));
    }
    
    // 目标sing-box路径
    let target_sing_box_path = Path::new(to).join("sing-box");
    
    // 尝试查找sing-box可执行文件
    if let Some(sing_box_path) = find_sing_box_executable(to) {
        info!("找到sing-box可执行文件: {}", sing_box_path.display());
        
        // 如果不在目标位置，尝试移动它
        if sing_box_path != target_sing_box_path {
            info!("将sing-box移动到目标位置: {}", target_sing_box_path.display());
            if let Err(e) = std::fs::rename(&sing_box_path, &target_sing_box_path) {
                error!("移动sing-box失败: {}, 尝试复制", e);
                
                // 如果移动失败（可能跨文件系统），尝试复制
                let mut src_file = match File::open(&sing_box_path) {
                    Ok(file) => file,
                    Err(e) => {
                        error!("打开源文件失败: {}", e);
                        return Err(format!("无法获取sing-box可执行文件: {}", e));
                    }
                };
                
                let mut dest_file = match File::create(&target_sing_box_path) {
                    Ok(file) => file,
                    Err(e) => {
                        error!("创建目标文件失败: {}", e);
                        return Err(format!("无法创建sing-box可执行文件: {}", e));
                    }
                };
                
                if let Err(e) = std::io::copy(&mut src_file, &mut dest_file) {
                    error!("复制文件内容失败: {}", e);
                    return Err(format!("无法复制sing-box可执行文件: {}", e));
                }
                
                // 删除原文件
                let _ = std::fs::remove_file(&sing_box_path);
            }
        }
    } else {
        error!("解压后未找到sing-box可执行文件");
        return Err("解压后未找到sing-box可执行文件".to_string());
    }
    
    // 设置执行权限
    #[cfg(target_os = "linux")]
    {
        if target_sing_box_path.exists() {
            info!("设置sing-box可执行权限");
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = target_sing_box_path.metadata() {
                let mut perms = metadata.permissions();
                perms.set_mode(0o755); // rwxr-xr-x
                if let Err(e) = std::fs::set_permissions(&target_sing_box_path, perms) {
                    error!("设置可执行权限失败: {}", e);
                } else {
                    info!("成功设置可执行权限");
                }
            }
            
            // 确认文件是否可执行
            let output = Command::new("file")
                .arg(&target_sing_box_path)
                .output();
                
            if let Ok(output) = output {
                let output_str = String::from_utf8_lossy(&output.stdout);
                info!("文件类型: {}", output_str);
                
                // 测试文件是否可被执行
                let test_output = Command::new(&target_sing_box_path)
                    .arg("version")
                    .output();
                
                match test_output {
                    Ok(test_output) => {
                        let version = String::from_utf8_lossy(&test_output.stdout);
                        info!("sing-box版本: {}", version);
                    },
                    Err(e) => {
                        error!("测试sing-box可执行性失败: {}", e);
                    }
                }
            }
        }
    }
    
    Ok(())
}

// 递归查找sing-box可执行文件
fn find_sing_box_executable(dir: &str) -> Option<std::path::PathBuf> {
    let dir_path = Path::new(dir);
    
    // 首先检查当前目录
    let direct_path = dir_path.join("sing-box");
    if direct_path.exists() && is_executable(&direct_path) {
        return Some(direct_path);
    }
    
    // 递归查找
    find_sing_box_in_dir(dir_path)
}

// 在目录中递归查找sing-box
fn find_sing_box_in_dir(dir: &Path) -> Option<std::path::PathBuf> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            
            // 如果是sing-box文件并且是可执行的
            if path.file_name().map_or(false, |name| name == "sing-box") && is_executable(&path) {
                return Some(path);
            }
            
            // 如果是目录，递归查找
            if path.is_dir() {
                if let Some(found) = find_sing_box_in_dir(&path) {
                    return Some(found);
                }
            }
        }
    }
    
    None
}

// 检查文件是否可执行
fn is_executable(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        if !path.exists() {
            return false;
        }
        
        if let Ok(metadata) = path.metadata() {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            return mode & 0o111 != 0; // 检查是否有执行权限
        }
        false
    }
    
    #[cfg(target_os = "windows")]
    {
        path.exists() && path.extension().map_or(false, |ext| ext == "exe")
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        path.exists()
    }
}

// 从代理下载，失败后尝试直接下载
pub async fn download_with_fallback<F>(
    original_url: &str, 
    path: &str, 
    progress_callback: F
) -> Result<(), String>
where
    F: Fn(u32) + Send + Clone + 'static,
{
    // 首先尝试通过代理下载 https://gh-proxy.com/https://github.com/...
    let proxy_url = format!("https://gh-proxy.com/{}", original_url);
    info!("尝试通过代理下载: {}", proxy_url);
    
    match download_file(proxy_url, path, progress_callback.clone()).await {
        Ok(_) => {
            info!("通过代理下载成功");
            Ok(())
        },
        Err(e) => {
            info!("代理下载失败: {}，尝试直接下载", e);
            // 代理下载失败，尝试直接下载
            download_file(original_url.to_string(), path, progress_callback).await
        }
    }
}
