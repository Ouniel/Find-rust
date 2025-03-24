mod finder;
mod utils;

use clap::{Arg, ArgAction, Command};
#[allow(unused_imports)]
use finder::{find_files_by_permission, get_windows_drives, FileInfo, SearchConfig};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::process;
use utils::{init_logger, log_to_file};

const USAGE: &str = r#"文件查找工具 (File Finder)

使用方法:
  file-finder [选项] 

基本选项:
  -keyword string   
        查找文件名包含指定关键字的文件
        示例: -keyword flag 或 -keyword back

  -perm string
        查找具有指定权限的文件:
        r  - 读权限
        w  - 写权限
        rw - 读写权限
        示例: -perm rw -global

  -time string
        查找指定时间后修改的文件
        格式: 2006-01-02
        示例: -time "2024-03-10"

  -global
        在根目录下进行全局搜索
        注意: Linux/Unix系统可能需要root权限

搜索范围:
  -dir string
        指定搜索的起始目录 (默认: ".")
        
  -depth int
        限制搜索的目录深度 (默认: -1, 表示不限制)

过滤选项:
  -types string
        按文件类型过滤，多个类型用逗号分隔
        示例: -types "txt,log,conf"
        
  -size int
        限制处理的文件大小（字节）
        示例: -size 1048576 (限制为1MB)
        
  -exclude string
        排除指定目录，多个目录用逗号分隔
        示例: -exclude "tmp,cache"

性能选项:
  -concurrent
        启用并发搜索 (默认: true)
        
  -workers int
        并发搜索的工作协程数 (默认: 5)
        
  -max-memory int
        限制内存使用（MB）
        示例: -max-memory 500

其他选项:
  -log
        是否记录日志到文件
        默认: false
"#;

/// 命令行参数解析
fn parse_args() -> clap::ArgMatches {
    Command::new("file-finder")
        .about("文件查找工具")
        .arg(
            Arg::new("keyword")
                .long("keyword")
                .help("查找文件名包含指定关键字的文件")
                .value_name("KEYWORD"),
        )
        .arg(
            Arg::new("perm")
                .long("perm")
                .help("查找具有指定权限的文件: r-读权限, w-写权限, rw-读写权限")
                .value_name("PERM"),
        )
        .arg(
            Arg::new("time")
                .long("time")
                .help("查找指定时间后修改的文件 (格式: YYYY-MM-DD)")
                .value_name("TIME"),
        )
        .arg(
            Arg::new("global")
                .long("global")
                .help("在根目录下进行全局搜索")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dir")
                .long("dir")
                .help("指定搜索的起始目录")
                .default_value(".")
                .value_name("DIR"),
        )
        .arg(
            Arg::new("depth")
                .long("depth")
                .help("限制搜索的目录深度")
                .value_name("DEPTH")
                .value_parser(clap::value_parser!(i32)),
        )
        .arg(
            Arg::new("types")
                .long("types")
                .help("按文件类型过滤，多个类型用逗号分隔")
                .value_name("TYPES"),
        )
        .arg(
            Arg::new("size")
                .long("size")
                .help("限制处理的文件大小（字节）")
                .value_name("SIZE")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("exclude")
                .long("exclude")
                .help("排除指定目录，多个目录用逗号分隔")
                .value_name("EXCLUDE"),
        )
        .arg(
            Arg::new("concurrent")
                .long("concurrent")
                .help("启用并发搜索")
                .action(ArgAction::SetTrue)
                .default_value("true"),
        )
        .arg(
            Arg::new("workers")
                .long("workers")
                .help("并发搜索的工作协程数")
                .default_value("5")
                .value_name("WORKERS")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("log")
                .long("log")
                .help("是否记录日志到文件")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("max-memory")
                .long("max-memory")
                .help("限制内存使用（MB），影响缓存大小")
                .value_name("MAX_MEMORY")
                .value_parser(clap::value_parser!(usize)),
        )
        .get_matches()
}

/// 创建搜索配置
fn create_search_config(matches: &clap::ArgMatches) -> SearchConfig {
    let mut config = SearchConfig::new();

    // 设置基本参数
    if let Some(dir) = matches.get_one::<String>("dir") {
        config.start_dir = dir.clone();
    }

    if let Some(depth) = matches.get_one::<i32>("depth") {
        if *depth >= 0 {
            config.max_depth = Some(*depth as usize);
        } else {
            config.max_depth = None;
        }
    }

    if let Some(size) = matches.get_one::<u64>("size") {
        config.size_limit = Some(*size);
    }

    config.concurrent = matches.get_flag("concurrent");

    if let Some(workers) = matches.get_one::<usize>("workers") {
        config.max_workers = *workers;
    }

    config.global_search = matches.get_flag("global");

    // 在全局搜索模式下，设置起始目录为根目录
    if config.global_search {
        if cfg!(windows) {
            // Windows下的全局搜索会在主函数中处理多个驱动器
            // 这里只设置一个默认值
            config.start_dir = "C:\\".to_string();
        } else {
            config.start_dir = "/".to_string();
        }
    }

    // 处理文件类型
    if let Some(types) = matches.get_one::<String>("types") {
        config.file_types = types.split(',').map(|s| s.trim().to_lowercase()).collect();
    }

    // 处理排除目录
    let mut exclude_dirs = vec![
        "$Recycle.Bin".to_string(),
        "$RECYCLE.BIN".to_string(),
        "System Volume Information".to_string(),
    ];

    if let Some(exclude) = matches.get_one::<String>("exclude") {
        let user_excludes: Vec<String> = exclude.split(',').map(|s| s.trim().to_string()).collect();
        exclude_dirs.extend(user_excludes);
    }

    config.exclude_dirs = exclude_dirs;

    // 处理内存限制
    if let Some(max_memory) = matches.get_one::<usize>("max-memory") {
        // 根据内存限制调整文件大小限制
        let memory_in_bytes = *max_memory * 1024 * 1024;

        // 如果没有显式设置文件大小限制，根据内存限制设置
        if config.size_limit.is_none() {
            // 将内存的10%用于文件内容缓存
            let content_memory = memory_in_bytes / 10;
            config.size_limit = Some((content_memory / 100) as u64); // 每个文件内容平均读取量
        }
    }

    config
}

/// 执行搜索并返回结果
fn execute_search(
    keyword: Option<&String>,
    perm_type: Option<&String>,
    time_limit: Option<&String>,
    config: &SearchConfig,
) -> HashMap<String, FileInfo> {
    let mut results = HashMap::new();

    // 处理文件名搜索
    if let Some(keyword) = keyword {
        // 直接搜索文件系统
        match finder::direct_search::find_files_directly(keyword, config) {
            Ok(files) => {
                results.extend(files);
            }
            Err(e) => {
                eprintln!("搜索文件时出错: {}", e);
            }
        }
    }

    // 处理权限搜索
    if let Some(perm) = perm_type {
        let perm_results = finder::permission_finder::find_files_by_permission(perm, config);
        if results.is_empty() {
            results = perm_results;
        } else {
            // 取交集
            results.retain(|path, _| perm_results.contains_key(path));
        }
    }

    // 处理时间搜索
    if let Some(time) = time_limit {
        let time_results = finder::time_finder::find_files_by_time(time, config);
        if results.is_empty() {
            results = time_results;
        } else {
            // 取交集
            results.retain(|path, _| time_results.contains_key(path));
        }
    }

    results
}

/// 打印搜索结果
fn print_search_results(results: &HashMap<String, FileInfo>, keyword: Option<&String>) {
    if results.is_empty() {
        if let Some(kw) = keyword {
            println!("\n❌ 未找到包含 '\x1b[33m{}\x1b[0m' 的文件", kw);
        } else {
            println!("\n❌ 未找到匹配的文件");
        }
        return;
    }

    // 使用彩色输出和Unicode图标
    println!("\n✅ 找到 \x1b[32m{}\x1b[0m 个匹配文件:\n", results.len());
    print_result_table(results);
}

/// 日志记录搜索结果
fn log_search_results(results: &HashMap<String, FileInfo>) -> io::Result<()> {
    let mut log_buf = format!("\n找到 {} 个匹配文件:\n\n", results.len());
    // 这里应该添加表格格式的日志，但为简化起见，仅记录基本信息
    for (path, info) in results {
        log_buf.push_str(&format!(
            "{} - 大小: {}, 修改时间: {}, 权限: {}\n",
            path, info.size, info.mod_time, info.permissions
        ));
    }
    log_to_file(&log_buf)
}

/// 格式化文件大小为可读格式
fn format_file_size(size: u64) -> String {
    const UNIT: u64 = 1024;
    if size < UNIT {
        return format!("{} B", size);
    }

    let mut size = size as f64;
    let mut exp = 0;

    while size >= UNIT as f64 && exp < 4 {
        size /= UNIT as f64;
        exp += 1;
    }

    let unit = match exp {
        1 => "KB",
        2 => "MB",
        3 => "GB",
        4 => "TB",
        _ => "B",
    };

    format!("{:.1} {}", size, unit)
}

/// 打印结果表格
fn print_result_table(results: &HashMap<String, FileInfo>) {
    // 定义列宽
    const PATH_WIDTH: usize = 46;
    const SIZE_WIDTH: usize = 10;
    const TIME_WIDTH: usize = 20;
    const PERM_WIDTH: usize = 6;
    const CONTENT_WIDTH: usize = 25;

    // 分隔线
    let line = "-".repeat(118);
    let dotline = ".".repeat(118);

    // 表头
    println!("{}", line);
    println!(
        "| {:<PATH_WIDTH$} | {:<SIZE_WIDTH$} | {:<TIME_WIDTH$} | {:<PERM_WIDTH$} | {:<CONTENT_WIDTH$} |",
        "文件路径", "文件大小", "修改时间", "权限", "内容摘要"
    );
    println!("{}", line);

    // 按路径排序
    let mut paths: Vec<&String> = results.keys().collect();
    paths.sort();

    // 上一个目录，用于确定是否需要显示分隔符
    let mut prev_dir = "";

    // 打印文件信息
    for (idx, path) in paths.iter().enumerate() {
        if let Some(info) = results.get(*path) {
            // 检查目录变化
            let current_dir = Path::new(path)
                .parent()
                .map_or("", |p| p.to_str().unwrap_or(""));

            if !prev_dir.is_empty() && current_dir != prev_dir {
                println!("{}", line);
            }
            prev_dir = current_dir;

            // 准备数据
            let formatted_size = format_file_size(info.size);
            let content = format_content(&info.content, CONTENT_WIDTH);

            // 处理长路径
            if path.len() > PATH_WIDTH {
                // 分割路径，确保字符边界安全
                let mut parts = Vec::new();
                let mut remaining = path.as_str();
                while !remaining.is_empty() {
                    // 确定当前行能显示的最大字符数
                    let mut chunk_len = PATH_WIDTH.min(remaining.len());

                    // 确保在字符边界处截断
                    while chunk_len > 0 && !remaining.is_char_boundary(chunk_len) {
                        chunk_len -= 1;
                    }

                    // 尝试找到目录分隔符来更合理地分割路径
                    if chunk_len == PATH_WIDTH {
                        for i in (0..chunk_len).rev() {
                            if i > 0
                                && (remaining.as_bytes()[i] == b'/'
                                    || remaining.as_bytes()[i] == b'\\')
                            {
                                // 在分隔符后分割
                                chunk_len = i + 1;
                                break;
                            }
                        }
                    }

                    parts.push(&remaining[..chunk_len]);
                    remaining = &remaining[chunk_len..];
                }

                // 第一行显示完整信息
                println!(
                    "| {:<PATH_WIDTH$} | {:<SIZE_WIDTH$} | {:<TIME_WIDTH$} | {:<PERM_WIDTH$} | {:<CONTENT_WIDTH$} |",
                    parts[0], formatted_size, info.mod_time, info.permissions, content
                );

                // 后续行只显示路径
                for part in parts.iter().skip(1) {
                    println!(
                        "| {:<PATH_WIDTH$} | {:<SIZE_WIDTH$} | {:<TIME_WIDTH$} | {:<PERM_WIDTH$} | {:<CONTENT_WIDTH$} |",
                        part, "", "", "", ""
                    );
                }
            } else {
                // 短路径，直接显示
                println!(
                    "| {:<PATH_WIDTH$} | {:<SIZE_WIDTH$} | {:<TIME_WIDTH$} | {:<PERM_WIDTH$} | {:<CONTENT_WIDTH$} |",
                    path, formatted_size, info.mod_time, info.permissions, content
                );
            }

            // 条目之间分隔符
            if idx < paths.len() - 1 {
                println!("{}", dotline);
            }
        }
    }

    // 表尾
    println!("{}", line);
}

/// 格式化内容显示
fn format_content(content: &str, max_width: usize) -> String {
    if content == "[二进制文件]" {
        return "[二进制]".to_string();
    }

    if content == "[读取内容失败]" {
        return "[读取失败]".to_string();
    }

    if content.is_empty() {
        return String::new();
    }

    // 获取第一行内容
    let first_line = content.lines().next().unwrap_or("");

    // 以下情况，尝试获取前两行内容
    if first_line.len() < max_width / 2 && content.contains('\n') {
        let mut lines = content.lines();
        let first = lines.next().unwrap_or("");
        if let Some(second) = lines.next() {
            if first.len() + second.len() + 3 <= max_width {
                // 3是省略号和分隔符的长度
                return format!("{} | {}", first, second);
            }
        }
    }

    // 否则只显示第一行
    if first_line.chars().count() <= max_width {
        first_line.to_string()
    } else {
        // 安全地截取字符，避免中文字符边界问题
        let mut result = String::new();
        let mut char_count = 0;
        for c in first_line.chars() {
            if char_count >= max_width - 3 {
                break;
            }
            result.push(c);
            char_count += 1;
        }
        format!("{}...", result)
    }
}

fn main() {
    // 如果没有参数，打印使用信息
    if std::env::args().len() <= 1 {
        println!("{}", USAGE);
        return;
    }

    // 解析命令行参数
    let matches = parse_args();

    // 初始化日志
    let enable_log = matches.get_flag("log");
    if let Err(e) = init_logger(enable_log) {
        eprintln!("初始化日志失败: {}", e);
    }

    // 创建搜索配置
    let mut config = create_search_config(&matches);

    // 获取搜索参数
    let keyword = matches.get_one::<String>("keyword");
    let perm_type = matches.get_one::<String>("perm");
    let time_limit = matches.get_one::<String>("time");

    // 添加内存使用情况报告
    if let Some(max_memory) = matches.get_one::<usize>("max-memory") {
        println!("内存限制: {} MB", max_memory);
    }

    // 检查是否有任何有效的搜索参数
    if keyword.is_none() && perm_type.is_none() && time_limit.is_none() {
        eprintln!("错误: 请至少指定一个搜索条件（-keyword、-perm 或 -time）");
        println!("\n{}", USAGE);
        process::exit(1);
    }

    // 全局搜索处理，枚举Windows驱动器
    if config.global_search && cfg!(windows) {
        let drives = get_windows_drives();
        if !drives.is_empty() {
            let mut all_results = HashMap::new();

            // 检查用户是否排除了特定盘符
            let has_excluded_drives = config.exclude_dirs.iter().any(|dir| {
                let dir = dir.to_lowercase();
                dir.len() == 1 || (dir.len() == 2 && dir.ends_with(':'))
            });

            if has_excluded_drives {
                println!("注意: 已检测到盘符排除，将跳过被排除的驱动器");
            }

            for drive in drives {
                let drive_str = drive.to_string_lossy().to_string();
                let drive_letter = drive_str
                    .chars()
                    .next()
                    .unwrap_or('?')
                    .to_lowercase()
                    .next()
                    .unwrap_or('?');

                // 检查此盘符是否被排除
                let is_excluded = config.exclude_dirs.iter().any(|dir| {
                    let dir = dir.to_lowercase();
                    let dir_letter = dir.chars().next().unwrap_or('?');
                    (dir.len() == 1 && dir_letter == drive_letter)
                        || (dir.len() == 2 && dir.ends_with(':') && dir.starts_with(drive_letter))
                });

                if is_excluded {
                    println!("跳过被排除的驱动器: {}", drive_str);
                    continue;
                }

                config.start_dir = drive_str;
                let results = execute_search(keyword, perm_type, time_limit, &config);
                all_results.extend(results);
            }

            if enable_log {
                if let Err(e) = log_search_results(&all_results) {
                    eprintln!("记录日志失败: {}", e);
                }
            }

            print_search_results(&all_results, keyword);
            return;
        }
    }

    // Linux系统的全局搜索处理
    #[cfg(unix)]
    if config.global_search {
        println!("开始Linux全局搜索...");

        // 检查排除目录中是否有以"/"开头的绝对路径
        let has_absolute_excludes = config.exclude_dirs.iter().any(|dir| dir.starts_with('/'));
        if has_absolute_excludes {
            println!("注意: 已检测到绝对路径排除，将跳过指定的目录");
            // 打印排除的绝对路径目录
            for dir in &config.exclude_dirs {
                if dir.starts_with('/') {
                    println!("将排除目录: {}", dir);
                }
            }
        }

        // 正常全局搜索
        config.start_dir = "/".to_string();
        let results = execute_search(keyword, perm_type, time_limit, &config);

        if enable_log {
            if let Err(e) = log_search_results(&results) {
                eprintln!("记录日志失败: {}", e);
            }
        }

        print_search_results(&results, keyword);
        return;
    }

    // 正常搜索
    let results = execute_search(keyword, perm_type, time_limit, &config);

    if enable_log {
        if let Err(e) = log_search_results(&results) {
            eprintln!("记录日志失败: {}", e);
        }
    }

    print_search_results(&results, keyword);

    // 报告内存使用
    report_memory_usage();
}

/// 报告当前内存使用情况（简易版本）
fn report_memory_usage() {
    // 在Windows上，我们可以通过Process API获取内存使用情况
    #[cfg(windows)]
    {
        use std::process::Command;

        // 使用tasklist命令获取当前进程的内存使用情况
        if let Ok(output) = Command::new("tasklist")
            .args(["/FI", "IMAGENAME eq find.exe", "/FO", "LIST"])
            .output()
        {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                // 提取内存使用部分
                if let Some(mem_idx) = output_str.find("内存使用") {
                    if let Some(end_idx) = output_str[mem_idx..].find('\n') {
                        let mem_info = &output_str[mem_idx..mem_idx + end_idx];
                        println!("{}", mem_info);
                        return;
                    }
                }

                // 英文系统尝试
                if let Some(mem_idx) = output_str.find("Mem Usage") {
                    if let Some(end_idx) = output_str[mem_idx..].find('\n') {
                        let mem_info = &output_str[mem_idx..mem_idx + end_idx];
                        println!("内存使用: {}", mem_info);
                        return;
                    }
                }
            }
        }

        println!("无法获取内存使用情况");
    }

    // 在Linux上，尝试读取/proc/self/status
    #[cfg(unix)]
    {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        if let Ok(file) = File::open("/proc/self/status") {
            let reader = BufReader::new(file);
            let mut vm_size = None;
            let mut vm_rss = None;

            for line in reader.lines() {
                if let Ok(line) = line {
                    if line.starts_with("VmSize:") {
                        vm_size = Some(line);
                    } else if line.starts_with("VmRSS:") {
                        vm_rss = Some(line);
                    }
                }
            }

            if let Some(size) = vm_size {
                println!("虚拟内存大小: {}", size.trim());
            }
            if let Some(rss) = vm_rss {
                println!("实际内存使用: {}", rss.trim());
            }

            return;
        }

        println!("无法获取内存使用情况");
    }
}
