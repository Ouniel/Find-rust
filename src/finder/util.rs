use crate::finder::config::{FileInfo, SearchConfig};
use chrono::Local;
use encoding_rs::{GB18030, GBK};
use std::fs::{self, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

/// 判断是否应该跳过指定文件
pub fn should_skip_file(path: &Path, metadata: &Metadata, config: &SearchConfig) -> bool {
    let path_str = match path.to_str() {
        Some(s) => s,
        None => return true, // 如果路径无法转换为字符串，则跳过
    };

    // 检查排除目录 - 特别处理路径
    for exclude_dir in &config.exclude_dirs {
        // 避免简单的子字符串匹配，标准化路径处理
        let normalized_path = path_str.replace('\\', "/").to_lowercase();
        let normalized_exclude = exclude_dir.replace('\\', "/").to_lowercase();

        // Windows特殊处理：排除整个盘符
        #[cfg(windows)]
        {
            // 排除整个盘符，如 "c" 应该匹配 "C:" 开头的所有路径
            // 兼容 "c", "C", "c:", "C:" 格式
            let clean_exclude = normalized_exclude.trim_end_matches(':');
            if clean_exclude.len() == 1
                && normalized_path.starts_with(&format!("{}:", clean_exclude))
            {
                return true;
            }
        }

        // Linux系统特殊处理
        #[cfg(unix)]
        {
            // 绝对路径精确匹配 - 处理完整路径如 "/sys/class/"
            if normalized_exclude.starts_with('/') {
                // 确保排除路径的尾部斜杠处理一致
                let exclude_clean = normalized_exclude.trim_end_matches('/');
                let path_clean = normalized_path.trim_end_matches('/');

                // 强制修复：直接判断路径字符串是否以排除规则开头
                if path_clean == exclude_clean || // 完全匹配
                   path_clean.starts_with(&format!("{}/", exclude_clean))
                // 路径以排除规则开始
                {
                    return true;
                }

                continue; // 对于绝对路径排除规则，不再执行下面的一般匹配
            }
        }

        // 一般路径匹配
        if normalized_path == normalized_exclude || // 完全匹配
           normalized_path.starts_with(&format!("{}/", normalized_exclude)) || // 排除目录是路径的前缀
           normalized_path.contains(&format!("/{}/", normalized_exclude)) || // 排除目录是路径中的一个组件
           normalized_path.ends_with(&format!("/{}", normalized_exclude))
        // 排除目录是路径的最后一个组件
        {
            return true;
        }
    }

    // 检查文件类型
    if !config.file_types.is_empty() && !metadata.is_dir() {
        if let Some(ext) = path.extension() {
            if let Some(ext_str) = ext.to_str() {
                let ext_lower = ext_str.to_lowercase();
                if !config.file_types.iter().any(|t| *t == ext_lower) {
                    return true;
                }
            }
        } else {
            // 没有扩展名且指定了文件类型过滤，则跳过
            return true;
        }
    }

    // 检查文件大小限制
    if let Some(size_limit) = config.size_limit {
        if metadata.len() > size_limit {
            return true;
        }
    }

    false
}

/// 获取文件信息
pub fn get_file_info(
    path: &Path,
    metadata: &Metadata,
    config: &SearchConfig,
) -> Result<FileInfo, std::io::Error> {
    let mut content = String::new();

    // 如果文件大小限制允许的话，读取文件内容
    let file_size = metadata.len();
    // 对大文件进行限制，默认只读取前8KB
    const MAX_READ_SIZE: u64 = 8 * 1024;
    if config.size_limit.is_none() || file_size <= config.size_limit.unwrap_or(u64::MAX) {
        // 只读取文本文件
        if !is_binary_path(path) {
            // 限制实际读取的内容大小，避免大文件消耗过多内存
            let read_size = if file_size > MAX_READ_SIZE {
                MAX_READ_SIZE
            } else {
                file_size
            };

            match read_file_sample(path, read_size) {
                Ok(c) => content = c,
                Err(_) => content = "[读取内容失败]".to_string(),
            }
        } else {
            content = "[二进制文件]".to_string();
        }
    }

    // 格式化修改时间
    let mod_time = match metadata.modified() {
        Ok(time) => {
            let dt = chrono::DateTime::<Local>::from(time);
            dt.format("%Y-%m-%d %H:%M:%S").to_string()
        }
        Err(_) => "未知时间".to_string(),
    };

    // 格式化权限
    let permissions = format_permissions(metadata);

    Ok(FileInfo {
        path: path.to_string_lossy().to_string(),
        size: metadata.len(),
        mod_time,
        permissions,
        content,
    })
}

/// 格式化文件权限
#[cfg(unix)]
fn format_permissions(metadata: &Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;
    format!("{:o}", metadata.permissions().mode() & 0o777)
}

/// 格式化文件权限 (Windows版本)
#[cfg(windows)]
fn format_permissions(metadata: &Metadata) -> String {
    use std::os::windows::fs::MetadataExt;

    let attrs = metadata.file_attributes();
    let mut result = String::new();

    if attrs & 0x1 != 0 {
        // FILE_ATTRIBUTE_READONLY
        result.push_str("r-");
    } else {
        result.push_str("rw");
    }

    if attrs & 0x2 != 0 {
        // FILE_ATTRIBUTE_HIDDEN
        result.push_str("h");
    }

    if attrs & 0x4 != 0 {
        // FILE_ATTRIBUTE_SYSTEM
        result.push_str("s");
    }

    result
}

/// 检查文件是否是二进制文件
fn is_binary_path(path: &Path) -> bool {
    // 简单通过扩展名判断常见的二进制文件类型
    let binary_extensions = [
        "exe", "dll", "so", "bin", "obj", "o", "a", "lib", "png", "jpg", "jpeg", "gif", "bmp",
        "ico", "tif", "tiff", "zip", "rar", "gz", "tar", "7z", "bz2", "xz", "pdf", "doc", "docx",
        "xls", "xlsx", "ppt", "pptx", "mp3", "mp4", "avi", "mov", "mkv", "flv", "wmv",
    ];

    if let Some(ext) = path.extension() {
        if let Some(ext_str) = ext.to_str() {
            return binary_extensions.contains(&ext_str.to_lowercase().as_str());
        }
    }

    // 对于没有扩展名的文件，读取前几个字节进行判断
    match fs::File::open(path) {
        Ok(mut file) => {
            let mut buffer = [0; 1024];
            match file.read(&mut buffer) {
                Ok(bytes_read) => {
                    // 包含0字节通常是二进制文件的标志
                    buffer[..bytes_read].contains(&0)
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

/// 只读取文件部分内容，减少内存占用
fn read_file_sample(path: &Path, sample_size: u64) -> Result<String, std::io::Error> {
    let mut file = fs::File::open(path)?;
    let mut buffer = Vec::with_capacity(sample_size as usize);

    // 只读取指定大小的内容
    let bytes_to_read = std::cmp::min(sample_size as usize, 8 * 1024); // 最多8KB
    let mut temp_buffer = vec![0; bytes_to_read];
    let bytes_read = file.read(&mut temp_buffer)?;
    buffer.extend_from_slice(&temp_buffer[..bytes_read]);

    // 如果文件比采样大，添加省略号提示
    let file_size = file.metadata()?.len();
    let truncated = (bytes_read as u64) < file_size;

    // 尝试作为UTF-8解码
    match String::from_utf8(buffer.clone()) {
        Ok(mut content) => {
            if truncated {
                content.push_str("\n... [内容被截断] ...");
            }
            Ok(content)
        }
        Err(_) => {
            // 尝试GBK
            let (mut cow, _, had_errors) = GBK.decode(&buffer);
            if !had_errors {
                if truncated {
                    cow.to_mut().push_str("\n... [内容被截断] ...");
                }
                return Ok(cow.into_owned());
            }

            // 尝试GB18030
            let (mut cow, _, had_errors) = GB18030.decode(&buffer);
            if !had_errors {
                if truncated {
                    cow.to_mut().push_str("\n... [内容被截断] ...");
                }
                return Ok(cow.into_owned());
            }

            // 如果都失败了，返回十六进制表示
            let prefix = &buffer[..std::cmp::min(64, buffer.len())];
            Ok(format!("[无法解码的内容，前64字节: {:x?}]", prefix))
        }
    }
}

/// 读取文件内容，尝试处理不同编码
#[allow(dead_code)]
fn read_file_content(path: &Path) -> Result<String, std::io::Error> {
    // 此函数保留用于向后兼容，现在内部调用采样函数
    read_file_sample(path, u64::MAX)
}

/// 获取Windows系统的所有驱动器
#[cfg(windows)]
pub fn get_windows_drives() -> Vec<PathBuf> {
    let mut drives = Vec::new();

    for c in b'A'..=b'Z' {
        let drive = format!("{}:\\", char::from(c));
        let path = PathBuf::from(&drive);
        if path.exists() {
            drives.push(path);
        }
    }

    drives
}

/// 获取Windows系统的所有驱动器 (非Windows系统的空实现)
#[cfg(not(windows))]
pub fn get_windows_drives() -> Vec<PathBuf> {
    Vec::new()
}
