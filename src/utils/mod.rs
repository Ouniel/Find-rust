use std::io;

mod logger;
pub mod progress;

pub use logger::init_logger;

/// 记录日志到文件
pub fn log_to_file(content: &str) -> io::Result<()> {
    logger::log_to_file(content)
}
