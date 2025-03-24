/// 文件信息结构体，用于存储文件的基本信息
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub mod_time: String,
    pub permissions: String,
    pub content: String,
}

/// 搜索配置结构体，用于配置搜索行为
#[derive(Debug, Clone)]
pub struct SearchConfig {
    pub start_dir: String,
    pub max_depth: Option<usize>,
    pub concurrent: bool,
    pub max_workers: usize,
    pub include_dir: bool,
    pub size_limit: Option<u64>,
    pub file_types: Vec<String>,
    pub exclude_dirs: Vec<String>,
    pub global_search: bool,
}

impl Default for SearchConfig {
    fn default() -> Self {
        SearchConfig {
            start_dir: ".".to_string(),
            max_depth: None,
            concurrent: true,
            max_workers: 5,
            include_dir: false,
            size_limit: None,
            file_types: Vec::new(),
            exclude_dirs: vec![".git".to_string(), "node_modules".to_string()],
            global_search: false,
        }
    }
}

impl SearchConfig {
    /// 创建新的搜索配置实例
    pub fn new() -> Self {
        Self::default()
    }
}
