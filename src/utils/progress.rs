use std::cell::{Cell, RefCell};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 进度条管理器
pub struct ProgressManager {
    #[allow(dead_code)]
    total: AtomicU64,
    current: AtomicU64,
    start_time: Instant,
    width: usize,
    last_update: Cell<Instant>,
    current_dir: RefCell<String>,
    #[allow(dead_code)]
    completed: bool,
}

impl ProgressManager {
    /// 创建新的进度条管理器
    pub fn new(width: usize) -> Self {
        ProgressManager {
            total: AtomicU64::new(0),
            current: AtomicU64::new(0),
            start_time: Instant::now(),
            width,
            last_update: Cell::new(Instant::now()),
            current_dir: RefCell::new(String::new()),
            completed: false,
        }
    }

    /// 启动进度条
    pub fn start(&self) {
        println!("开始搜索文件...");
        // 初始化进度条
        self.update_progress_bar();
    }

    /// 停止进度条
    pub fn stop(&self, success: bool) {
        // 清除进度条
        self.clear_progress_bar();
        if success {
            let elapsed = self.start_time.elapsed();
            println!(
                "搜索完成，共处理 {} 个文件，用时 {:.2} 秒",
                self.current.load(Ordering::Relaxed),
                elapsed.as_secs_f64()
            );
        } else {
            println!("搜索中断");
        }
    }

    /// 增加进度
    pub fn increment(&self) {
        self.current.fetch_add(1, Ordering::Relaxed);

        // 每100ms更新一次进度条，避免频繁输出
        if self.last_update.get().elapsed() > Duration::from_millis(100) {
            self.update_progress_bar();
        }
    }

    /// 设置当前搜索目录
    pub fn set_current_dir(&self, dir: &str) {
        // 不再打印目录，只更新内部状态
        *self.current_dir.borrow_mut() = dir.to_string();
    }

    /// 设置进度条消息
    #[allow(dead_code)]
    pub fn set_message(&self, msg: &str) {
        self.clear_progress_bar();
        println!("{}", msg);
        self.update_progress_bar();
    }

    /// 设置总数
    #[allow(dead_code)]
    pub fn set_total(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
    }

    /// 获取当前进度
    pub fn get_current(&self) -> u64 {
        self.current.load(Ordering::Relaxed)
    }

    /// 更新进度条
    fn update_progress_bar(&self) {
        let current = self.current.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed();
        let speed = if elapsed.as_secs() > 0 {
            current as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        // 构建进度条
        let mut progress_text = format!(
            "\r已处理: {} 个文件 | 速度: {:.1} 文件/秒 | 用时: {:.1}s ",
            current,
            speed,
            elapsed.as_secs_f64()
        );

        // 使用Unicode字符构建进度条
        let bar_width = self.width.saturating_sub(progress_text.len());

        // 添加旋转指示器 - 使用Unicode字符
        let spinner = ["◐", "◓", "◑", "◒"];
        let spinner_pos = (elapsed.as_millis() / 100) % spinner.len() as u128;

        // 使用Unicode进度字符
        progress_text.push_str(&format!(
            "{} {}",
            spinner[spinner_pos as usize],
            "▮".repeat(bar_width.min(50))
        ));

        // 输出进度条
        print!("{}", progress_text);
        io::stdout().flush().unwrap();

        // 更新最后更新时间
        self.last_update.set(Instant::now());
    }

    /// 清除进度条
    fn clear_progress_bar(&self) {
        print!("\r");
        for _ in 0..self.width {
            print!(" ");
        }
        print!("\r");
        io::stdout().flush().unwrap();
    }
}

/// 创建共享进度条
#[allow(dead_code)]
pub fn create_progress_bar(width: usize) -> Arc<ProgressManager> {
    Arc::new(ProgressManager::new(width))
}
