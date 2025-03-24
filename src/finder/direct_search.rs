use crate::finder::config::{FileInfo, SearchConfig};
use crate::finder::util::{get_file_info, should_skip_file};
use crate::utils::progress::ProgressManager;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::sync::Arc;
use std::time::SystemTime;
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

/// 直接搜索文件系统，不使用索引
pub fn find_files_directly(
    keyword: &str,
    config: &SearchConfig,
) -> Result<HashMap<String, FileInfo>, io::Error> {
    let mut results = HashMap::new();
    let keyword_lower = keyword.to_lowercase();

    // 创建进度条 - 使用更宽的宽度
    let progress = Arc::new(ProgressManager::new(100));
    progress.start();

    // 设置起始目录
    let start_dir = &config.start_dir;
    // 不再显示当前目录，只设置内部状态
    progress.set_current_dir(start_dir);

    // 遍历文件系统，添加过滤器在遍历前跳过被排除的目录
    let walker = WalkDir::new(start_dir)
        .follow_links(true)
        .max_depth(config.max_depth.unwrap_or(usize::MAX))
        .into_iter()
        .filter_entry(|e| !should_skip_dir(e, config)); // 在遍历之前筛选目录

    // 开始计时
    let start_time = SystemTime::now();
    let mut _matched = 0;

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();

        // 更新进度
        progress.increment();

        // 不再显示当前处理的目录，只更新进度条
        // 仍可以更新内部状态，但不再打印目录信息
        if let Some(parent) = path.parent() {
            if let Some(dir_str) = parent.to_str() {
                if progress.get_current() % 5000 == 0 {
                    progress.set_current_dir(dir_str);
                }
            }
        }

        // 获取文件元数据
        match fs::metadata(path) {
            Ok(metadata) => {
                // 检查是否应该跳过 (这里保留，因为还需要做其他检查如文件类型、大小等)
                if should_skip_file(path, &metadata, config) {
                    continue;
                }

                // 检查文件名是否匹配关键字
                let path_str = path.to_string_lossy().to_lowercase();
                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_lowercase();

                // 检查文件名或路径是否包含关键字
                let name_match = file_name.contains(&keyword_lower);
                let path_match = path_str.contains(&keyword_lower);

                // 如果文件名或路径匹配，或者需要检查内容
                if name_match || path_match || config.size_limit.is_some() {
                    // 获取文件信息
                    match get_file_info(path, &metadata, config) {
                        Ok(file_info) => {
                            // 如果文件名或路径匹配，直接添加到结果
                            if name_match || path_match {
                                results.insert(path.to_string_lossy().to_string(), file_info);
                                _matched += 1;
                            }
                            // 否则，检查文件内容是否匹配
                            else if config.size_limit.is_some() && !metadata.is_dir() {
                                // 检查文件内容是否包含关键字
                                if file_info.content.to_lowercase().contains(&keyword_lower) {
                                    results.insert(path.to_string_lossy().to_string(), file_info);
                                    _matched += 1;
                                }
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
            Err(_) => continue,
        }
    }

    // 停止进度条并输出结果
    progress.stop(true);

    // 输出搜索完成信息
    if let Ok(elapsed) = start_time.elapsed() {
        println!(
            "搜索完成，总共找到 {} 个匹配文件，用时 {:.2} 秒",
            results.len(),
            elapsed.as_secs_f64()
        );
    }

    Ok(results)
}
