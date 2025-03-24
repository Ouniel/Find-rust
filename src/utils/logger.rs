use log::{LevelFilter, SetLoggerError};
use simple_logger::SimpleLogger;
use std::fs::OpenOptions;
use std::io::Write;

/// 初始化日志系统
pub fn init_logger(enable_log: bool) -> Result<(), SetLoggerError> {
    if enable_log {
        SimpleLogger::new().with_level(LevelFilter::Info).init()
    } else {
        SimpleLogger::new().with_level(LevelFilter::Off).init()
    }
}

/// 记录搜索结果到日志文件
pub fn log_to_file(message: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("file_finder.log")?;

    writeln!(file, "{}", message)?;
    Ok(())
}
