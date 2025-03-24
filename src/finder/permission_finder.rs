use crate::finder::config::{FileInfo, SearchConfig};
use crate::finder::util::{get_file_info, should_skip_file};
use std::collections::HashMap;
use std::fs::{self, Metadata};
use std::path::Path;
use walkdir::{DirEntry, WalkDir};

/// 判断是否应该跳过此目录（在遍历前检查）
#[cfg(unix)]
fn should_skip_dir(entry: &DirEntry, config: &SearchConfig) -> bool {
    let path = entry.path();
    if !entry.file_type().is_dir() {
        return false; // 不是目录，不做跳过检查
    }

    let path_str = match path.to_str() {
        Some(s) => s,
        None => return true, // 如果路径无法转换为字符串，则跳过
    };

    // 检查排除目录（简化版，只进行Linux排除检查）
    for exclude_dir in &config.exclude_dirs {
        // 标准化路径处理
        let normalized_path = path_str.replace('\\', "/").to_lowercase();
        let normalized_exclude = exclude_dir.replace('\\', "/").to_lowercase();

        // Linux系统下检查绝对路径
        if normalized_exclude.starts_with('/') {
            // 确保排除路径的尾部斜杠处理一致
            let exclude_clean = normalized_exclude.trim_end_matches('/');
            let path_clean = normalized_path.trim_end_matches('/');

            // 判断路径字符串是否以排除规则开头
            if path_clean == exclude_clean || // 完全匹配
               path_clean.starts_with(&format!("{}/", exclude_clean))
            // 路径以排除规则开始
            {
                return true;
            }

            continue; // 对于绝对路径排除规则，不再执行下面的一般匹配
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

    false
}

#[cfg(not(unix))]
fn should_skip_dir(_entry: &DirEntry, _config: &SearchConfig) -> bool {
    false // 仅在Linux系统实现时进行有效检查，其他系统不使用这个预检测
}

/// 根据权限类型查找文件
pub fn find_files_by_permission(
    perm_type: &str,
    config: &SearchConfig,
) -> HashMap<String, FileInfo> {
    let mut results = HashMap::new();

    // 遍历文件系统，添加过滤器在遍历前跳过被排除的目录
    let walker = WalkDir::new(&config.start_dir)
        .follow_links(true)
        .max_depth(config.max_depth.unwrap_or(usize::MAX))
        .into_iter()
        .filter_entry(|e| !should_skip_dir(e, config)); // 在遍历之前筛选目录

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();
        let metadata = match fs::metadata(path) {
            Ok(meta) => meta,
            Err(_) => continue,
        };

        // 应用配置中的搜索限制
        if should_skip_file(path, &metadata, config) {
            continue;
        }

        // 如果是目录且不包括目录，则跳过
        if metadata.is_dir() && !config.include_dir {
            continue;
        }

        // 检查文件权限
        if matches_permission(perm_type, &metadata, path) {
            // 获取文件信息
            match get_file_info(path, &metadata, config) {
                Ok(file_info) => {
                    if let Some(path_str) = path.to_str() {
                        results.insert(path_str.to_string(), file_info);
                    }
                }
                Err(_) => continue,
            }
        }
    }

    results
}

/// 检查文件是否符合指定的权限类型
#[cfg(unix)]
fn matches_permission(perm_type: &str, metadata: &Metadata, _path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;

    match perm_type {
        "r" => (mode & 0o444) != 0,       // 任何人可读
        "w" => (mode & 0o222) != 0,       // 任何人可写
        "rw" => (mode & 0o666) == 0o666,  // 任何人可读可写
        "x" => (mode & 0o111) != 0,       // 任何人可执行
        "rx" => (mode & 0o555) == 0o555,  // 任何人可读可执行
        "rwx" => (mode & 0o777) == 0o777, // 任何人可读可写可执行
        "suid" => (mode & 0o4000) != 0,   // 设置用户ID位
        "sgid" => (mode & 0o2000) != 0,   // 设置组ID位
        "sticky" => (mode & 0o1000) != 0, // 粘滞位
        _ => false,
    }
}

/// Windows版本的权限匹配
#[cfg(windows)]
fn matches_permission(perm_type: &str, metadata: &Metadata, _path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;

    let attrs = metadata.file_attributes();

    // Windows权限处理简化版
    match perm_type {
        "r" => true,                      // Windows文件默认可读
        "w" => (attrs & 0x1) == 0,        // 不是只读
        "rw" => (attrs & 0x1) == 0,       // 不是只读
        "hidden" => (attrs & 0x2) != 0,   // 隐藏文件
        "system" => (attrs & 0x4) != 0,   // 系统文件
        "archive" => (attrs & 0x20) != 0, // 存档文件
        _ => false,
    }
}
