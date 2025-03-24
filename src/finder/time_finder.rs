use crate::finder::config::{FileInfo, SearchConfig};
use crate::finder::util::{get_file_info, should_skip_file};
use chrono::DateTime;
use std::collections::HashMap;
use std::fs;
use std::time::{Duration, SystemTime};
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

/// 查找指定时间后修改的文件，返回FileInfo集合
pub fn find_files_by_time(time_str: &str, config: &SearchConfig) -> HashMap<String, FileInfo> {
    let mut results = HashMap::new();

    // 解析时间字符串
    let limit_time = match parse_time(time_str) {
        Ok(time) => time,
        Err(e) => {
            eprintln!("无法解析时间: {}", e);
            return results;
        }
    };

    // 使用新的方法查找符合时间条件的文件（带有目录预过滤功能）
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

        // 检查修改时间
        if let Ok(mod_time) = metadata.modified() {
            if mod_time > limit_time {
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
    }

    results
}

/// 查找指定时间后修改的文件，返回路径列表
#[allow(dead_code)]
pub fn find_modified_files(limit_time: SystemTime, config: &SearchConfig) -> Vec<String> {
    let mut results = Vec::new();

    // 使用新的目录预过滤功能
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

        // 检查修改时间
        if let Ok(mod_time) = metadata.modified() {
            if mod_time > limit_time {
                if let Some(path_str) = path.to_str() {
                    results.push(path_str.to_string());
                }
            }
        }
    }

    results
}

/// 将日期字符串解析为系统时间
pub fn parse_time(time_str: &str) -> Result<SystemTime, &'static str> {
    // 检查是否是预定义的关键字
    match time_str {
        "today" => {
            let now = SystemTime::now();
            let dur = Duration::from_secs(24 * 60 * 60); // 一天的秒数
            return now.checked_sub(dur).ok_or("无法计算时间");
        }
        "yesterday" => {
            let now = SystemTime::now();
            let dur = Duration::from_secs(2 * 24 * 60 * 60); // 两天的秒数
            return now.checked_sub(dur).ok_or("无法计算时间");
        }
        "week" => {
            let now = SystemTime::now();
            let dur = Duration::from_secs(7 * 24 * 60 * 60); // 一周的秒数
            return now.checked_sub(dur).ok_or("无法计算时间");
        }
        "month" => {
            let now = SystemTime::now();
            let dur = Duration::from_secs(30 * 24 * 60 * 60); // 一个月的秒数(近似)
            return now.checked_sub(dur).ok_or("无法计算时间");
        }
        _ => {
            // 尝试解析日期格式
            let parsed = DateTime::parse_from_str(
                &format!("{} 00:00:00 +0800", time_str),
                "%Y-%m-%d %H:%M:%S %z",
            )
            .map_err(|_| "无效的日期格式，请使用YYYY-MM-DD格式")?;

            Ok(SystemTime::from(parsed))
        }
    }
}
