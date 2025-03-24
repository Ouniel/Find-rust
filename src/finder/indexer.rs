use crate::finder::config::{FileInfo, SearchConfig};
use crate::finder::util::{get_file_info, should_skip_file};
use crate::utils::ProgressManager;
use once_cell::sync::OnceCell;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};
use walkdir::WalkDir;

/// 文件索引信息 - 精简字段以减少内存占用
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FileIndex {
    // 不再存储完整路径字符串，改用PathBuf
    path_buf: PathBuf,
    // 文件名单独存储避免重复
    name: String,
    size: u64,
    mod_time: SystemTime,
    is_dir: bool,
    // 权限使用更紧凑的格式
    permissions_code: u32,
    // 添加访问计数，用于垃圾回收策略
    access_count: u32,
    last_access: Instant,
}

/// 索引器
pub struct Indexer {
    file_indices: RwLock<HashMap<String, FileIndex>>,
    name_indices: RwLock<HashMap<String, Vec<String>>>,
    last_update: RwLock<Option<SystemTime>>,
    // 添加索引容量限制
    max_files: usize,
    // 访问数据，用于垃圾回收
    gc_threshold: usize,
    last_gc: RwLock<Instant>,
}

// 单例实现
static INSTANCE: OnceCell<Arc<Indexer>> = OnceCell::new();

impl Indexer {
    /// 获取索引器实例
    pub fn get_instance() -> Arc<Indexer> {
        INSTANCE
            .get_or_init(|| {
                Arc::new(Indexer {
                    file_indices: RwLock::new(HashMap::new()),
                    name_indices: RwLock::new(HashMap::new()),
                    last_update: RwLock::new(None),
                    // 默认限制索引100万文件
                    max_files: 1_000_000,
                    // 当索引大小达到阈值的80%时触发垃圾回收
                    gc_threshold: 800_000,
                    last_gc: RwLock::new(Instant::now()),
                })
            })
            .clone()
    }

    /// 检查索引是否为空
    pub fn is_empty(&self) -> bool {
        self.file_indices.read().unwrap().is_empty()
    }

    /// 设置最大文件索引数量
    pub fn set_max_files(&self, max_files: usize) {
        let mut max_files_value = max_files;
        // 设置最小值，确保至少可以索引一些文件
        if max_files_value < 1000 {
            max_files_value = 1000;
        }

        // 使用unsafe来修改单例实例中的max_files
        // 这是安全的，因为我们只是修改一个简单的值且只在程序初始化时调用
        unsafe {
            let self_mut = self as *const Indexer as *mut Indexer;
            (*self_mut).max_files = max_files_value;
            // 同时更新垃圾回收阈值
            (*self_mut).gc_threshold = max_files_value * 8 / 10;
        }
    }

    /// 执行垃圾回收，删除不常用的索引项
    fn perform_garbage_collection(&self) {
        // 检查是否需要垃圾回收
        let current_size;
        {
            let indices = self.file_indices.read().unwrap();
            current_size = indices.len();

            // 如果索引大小小于阈值，则不需要垃圾回收
            if current_size < self.gc_threshold {
                return;
            }

            // 检查上次垃圾回收时间，避免频繁GC
            let last_gc = *self.last_gc.read().unwrap();
            if last_gc.elapsed() < Duration::from_secs(60) {
                return;
            }
        }

        eprintln!("[索引] 执行垃圾回收，当前索引大小: {}", current_size);

        // 计算需要删除的索引数量
        let to_delete = current_size - self.gc_threshold;

        // 获取索引的所有路径及其访问计数
        let mut path_metrics: Vec<(String, u32, Instant)> = {
            let indices = self.file_indices.read().unwrap();
            indices
                .iter()
                .map(|(path, index)| (path.clone(), index.access_count, index.last_access))
                .collect()
        };

        // 根据访问频率和最后访问时间排序
        path_metrics.sort_by(|a, b| {
            // 优先删除访问计数低的
            let count_cmp = a.1.cmp(&b.1);
            if count_cmp != std::cmp::Ordering::Equal {
                return count_cmp;
            }

            // 访问计数相同时，删除最久未访问的
            a.2.cmp(&b.2)
        });

        // 获取要删除的路径
        let delete_paths: HashSet<String> = path_metrics
            .iter()
            .take(to_delete)
            .map(|(path, _, _)| path.clone())
            .collect();

        // 删除指定的索引
        {
            let mut file_indices = self.file_indices.write().unwrap();
            let mut name_indices = self.name_indices.write().unwrap();

            // 从文件索引中删除
            for path in &delete_paths {
                if let Some(index) = file_indices.remove(path) {
                    // 从名称索引中也删除这个路径
                    if let Some(paths) = name_indices.get_mut(&index.name) {
                        paths.retain(|p| p != path);
                        // 如果名称对应的路径列表为空，则删除整个条目
                        if paths.is_empty() {
                            name_indices.remove(&index.name);
                        }
                    }
                }
            }
        }

        // 更新最后垃圾回收时间
        *self.last_gc.write().unwrap() = Instant::now();

        // 记录垃圾回收结果
        eprintln!("[索引] 垃圾回收完成，删除 {} 个索引项", delete_paths.len());
    }

    /// 获取权限编码 - 避免存储权限字符串
    fn get_permission_code(path: &Path, metadata: &fs::Metadata) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o777
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes()
        }

        #[cfg(not(any(windows, unix)))]
        {
            0
        }
    }

    /// 构建文件索引
    pub fn build_index(
        &self,
        start_dir: &str,
        config: &SearchConfig,
    ) -> Result<(), std::io::Error> {
        // 在构建新索引前执行垃圾回收
        self.perform_garbage_collection();

        // 创建进度条
        let progress = ProgressManager::new(50);
        progress.start();

        // 设置并发参数
        let workers = if config.concurrent {
            config.max_workers
        } else {
            1
        };

        // 使用通道收集文件索引
        let (sender, receiver) = std::sync::mpsc::channel();
        let sender = Arc::new(Mutex::new(sender));

        // 添加计数器来限制索引的文件数量
        let counter = Arc::new(Mutex::new(0));
        let max_files = self.max_files;

        // 创建线程池
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();

        // 遍历文件系统
        let walker = WalkDir::new(start_dir)
            .follow_links(true)
            .max_depth(config.max_depth.unwrap_or(usize::MAX));

        // 启动一个线程来接收结果
        let receiver_thread = std::thread::spawn(move || {
            let mut file_indices = HashMap::new();
            let mut name_indices: HashMap<String, Vec<String>> = HashMap::new();

            for file_index in receiver {
                let index: FileIndex = file_index;
                let path_str = index.path_buf.to_string_lossy().to_string();

                name_indices
                    .entry(index.name.clone())
                    .or_default()
                    .push(path_str.clone());

                file_indices.insert(path_str, index);
            }

            (file_indices, name_indices)
        });

        // 使用线程池处理文件
        pool.install(|| {
            walker.into_iter().filter_map(|e| e.ok()).for_each(|entry| {
                let path = entry.path();
                let sender = Arc::clone(&sender);
                let progress = &progress;
                let counter = Arc::clone(&counter);

                // 先检查是否已达到索引文件数量限制
                {
                    let count = *counter.lock().unwrap();
                    if count >= max_files {
                        return; // 达到限制，不再索引
                    }
                }

                // 更新内部目录状态，但不打印
                if entry.file_type().is_dir() {
                    progress.set_current_dir(&path.to_string_lossy());
                }

                match fs::metadata(path) {
                    Ok(metadata) => {
                        // 检查是否应该跳过
                        if !should_skip_file(path, &metadata, config) {
                            // 创建文件索引
                            if let Some(file_name) = path.file_name() {
                                if let Some(file_name_str) = file_name.to_str() {
                                    {
                                        // 增加计数器
                                        let mut count = counter.lock().unwrap();
                                        *count += 1;

                                        // 定期显示已索引文件数
                                        if *count % 10000 == 0 {
                                            progress
                                                .set_message(&format!("已索引 {} 个文件", *count));
                                        }

                                        // 达到限制也立即返回
                                        if *count >= max_files {
                                            progress.set_message(&format!(
                                                "已达到索引上限 {} 个文件",
                                                max_files
                                            ));
                                            return;
                                        }
                                    }

                                    let file_index = FileIndex {
                                        path_buf: path.to_path_buf(),
                                        name: file_name_str.to_string(),
                                        size: metadata.len(),
                                        mod_time: metadata.modified().unwrap_or(SystemTime::now()),
                                        is_dir: metadata.is_dir(),
                                        permissions_code: Self::get_permission_code(
                                            path, &metadata,
                                        ),
                                        // 初始化访问计数和最后访问时间
                                        access_count: 0,
                                        last_access: Instant::now(),
                                    };

                                    if let Ok(sender) = sender.lock() {
                                        let _ = sender.send(file_index);
                                    }
                                }
                            }
                        }

                        // 更新进度
                        progress.increment();
                    }
                    Err(_) => {
                        // 忽略无法访问的文件
                        progress.increment();
                    }
                }
            });
        });

        // 关闭发送通道，让接收线程能够结束
        drop(sender);

        // 等待接收线程完成并获取结果
        let (file_indices, name_indices) = receiver_thread.join().unwrap();

        // 更新索引
        *self.file_indices.write().unwrap() = file_indices;
        *self.name_indices.write().unwrap() = name_indices;
        *self.last_update.write().unwrap() = Some(SystemTime::now());

        // 获取索引大小信息
        let index_size = self.file_indices.read().unwrap().len();
        progress.set_message(&format!("索引完成，共索引 {} 个文件", index_size));

        progress.stop(true);
        Ok(())
    }

    /// 获取格式化的权限字符串
    fn format_permissions_from_code(&self, code: u32) -> String {
        #[cfg(unix)]
        {
            format!("{:o}", code & 0o777)
        }

        #[cfg(windows)]
        {
            let attrs = code;
            let mut result = String::with_capacity(4);

            if attrs & 0x1 != 0 {
                // FILE_ATTRIBUTE_READONLY
                result.push_str("r-");
            } else {
                result.push_str("rw");
            }

            if attrs & 0x2 != 0 {
                // FILE_ATTRIBUTE_HIDDEN
                result.push('h');
            }

            if attrs & 0x4 != 0 {
                // FILE_ATTRIBUTE_SYSTEM
                result.push('s');
            }

            result
        }

        #[cfg(not(any(windows, unix)))]
        {
            "----".to_string()
        }
    }

    /// 更新文件的访问计数
    fn update_access_stats(&self, path: &str) {
        let mut file_indices = self.file_indices.write().unwrap();
        if let Some(index) = file_indices.get_mut(path) {
            index.access_count += 1;
            index.last_access = Instant::now();
        }
    }

    /// 搜索匹配关键词的文件
    pub fn search(
        &self,
        keyword: &str,
        config: &SearchConfig,
    ) -> Result<HashMap<String, FileInfo>, std::io::Error> {
        let mut results = HashMap::new();
        let keyword_lower = keyword.to_lowercase();

        // 检查索引是否过期
        if let Some(last_update) = *self.last_update.read().unwrap() {
            if SystemTime::now()
                .duration_since(last_update)
                .unwrap_or(Duration::from_secs(0))
                > Duration::from_secs(30 * 60)
            {
                eprintln!("[索引] 索引已过期，建议重建");
            }
        }

        // 使用名称索引快速查找
        let name_indices = self.name_indices.read().unwrap();
        let file_indices = self.file_indices.read().unwrap();

        // 首先尝试完全匹配文件名
        for (name, paths) in name_indices.iter() {
            if name.to_lowercase().contains(&keyword_lower) {
                for path in paths {
                    if let Some(index) = file_indices.get(path) {
                        // 将文件索引转换为文件信息
                        let mod_time = match index.mod_time.elapsed() {
                            Ok(elapsed) => {
                                let now = SystemTime::now();
                                let mod_time = now - elapsed;
                                let dt = chrono::DateTime::<chrono::Local>::from(mod_time);
                                dt.format("%Y-%m-%d %H:%M:%S").to_string()
                            }
                            Err(_) => "未知时间".to_string(),
                        };

                        let permissions = self.format_permissions_from_code(index.permissions_code);

                        results.insert(
                            path.clone(),
                            FileInfo {
                                path: path.clone(),
                                size: index.size,
                                mod_time,
                                permissions,
                                // 不预先读取文件内容，减少内存占用
                                content: String::new(),
                            },
                        );

                        // 更新访问统计（克隆路径以避免引用问题）
                        let path_clone = path.clone();
                        std::thread::spawn(move || {
                            let indexer = Indexer::get_instance();
                            indexer.update_access_stats(&path_clone);
                        });
                    }
                }
            }
        }

        // 如果没有匹配的结果，尝试模糊搜索路径
        if results.is_empty() {
            for (path, index) in file_indices.iter() {
                if path.to_lowercase().contains(&keyword_lower) {
                    let mod_time = match index.mod_time.elapsed() {
                        Ok(elapsed) => {
                            let now = SystemTime::now();
                            let mod_time = now - elapsed;
                            let dt = chrono::DateTime::<chrono::Local>::from(mod_time);
                            dt.format("%Y-%m-%d %H:%M:%S").to_string()
                        }
                        Err(_) => "未知时间".to_string(),
                    };

                    let permissions = self.format_permissions_from_code(index.permissions_code);

                    results.insert(
                        path.clone(),
                        FileInfo {
                            path: path.clone(),
                            size: index.size,
                            mod_time,
                            permissions,
                            // 不预先读取文件内容，减少内存占用
                            content: String::new(),
                        },
                    );

                    // 更新访问统计（克隆路径以避免引用问题）
                    let path_clone = path.clone();
                    std::thread::spawn(move || {
                        let indexer = Indexer::get_instance();
                        indexer.update_access_stats(&path_clone);
                    });
                }
            }
        }

        // 如果结果数量超过限制，可能需要进行垃圾回收
        if self.file_indices.read().unwrap().len() >= self.gc_threshold {
            // 异步执行垃圾回收
            std::thread::spawn(move || {
                let indexer = Indexer::get_instance();
                indexer.perform_garbage_collection();
            });
        }

        // 如果仍然没有结果，尝试内容搜索（如果配置允许）
        if results.is_empty() && config.size_limit.is_some() {
            // 遍历每个文件，检查内容
            for (path, index) in file_indices.iter() {
                // 跳过过大的文件
                if let Some(size_limit) = config.size_limit {
                    if index.size > size_limit {
                        continue;
                    }
                }

                // 跳过目录
                if index.is_dir {
                    continue;
                }

                // 检查文件内容是否包含关键词
                if let Ok(metadata) = fs::metadata(&index.path_buf) {
                    if let Ok(file_info) = get_file_info(&index.path_buf, &metadata, config) {
                        if file_info.content.to_lowercase().contains(&keyword_lower) {
                            results.insert(path.clone(), file_info);

                            // 更新访问统计（克隆路径以避免引用问题）
                            let path_clone = path.clone();
                            std::thread::spawn(move || {
                                let indexer = Indexer::get_instance();
                                indexer.update_access_stats(&path_clone);
                            });
                        }
                    }
                }
            }
        }

        Ok(results)
    }
}
