use crate::finder::config::FileInfo;
use crate::finder::config::SearchConfig;
use crate::finder::direct_search;
use std::collections::HashMap;

/// 根据关键词查找文件
#[allow(dead_code)]
pub fn find_files_by_keyword(keyword: &str, config: &SearchConfig) -> HashMap<String, FileInfo> {
    // 直接使用文件系统搜索，不再使用索引
    match direct_search::find_files_directly(keyword, config) {
        Ok(results) => results,
        Err(e) => {
            eprintln!("搜索失败: {}", e);
            HashMap::new()
        }
    }
}
