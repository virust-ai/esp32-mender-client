#[macro_export]
macro_rules! log_error {
    ($fmt:expr) => {
        log::error!(target: "", "[{}:{}] {}", file!(), line!(), $fmt);
    };
    ($fmt:expr, $($arg:tt)*) => {
        log::error!(target: "", "[{}:{}] {}", file!(), line!(), format_args!($fmt, $($arg)*));
    };
}

#[macro_export]
macro_rules! log_warn {
    ($fmt:expr) => {
        log::warn!(target: "", "[{}:{}] {}", file!(), line!(), $fmt);
    };
    ($fmt:expr, $($arg:tt)*) => {
        log::warn!(target: "", "[{}:{}] {}", file!(), line!(), format_args!($fmt, $($arg)*));
    };
}

#[macro_export]
macro_rules! log_info {
    ($fmt:expr) => {
        log::info!(target: "", "[{}:{}] {}", file!(), line!(), $fmt);
    };
    ($fmt:expr, $($arg:tt)*) => {
        log::info!(target: "", "[{}:{}] {}", file!(), line!(), format_args!($fmt, $($arg)*));
    };
}

#[macro_export]
macro_rules! log_debug {
    ($fmt:expr) => {
        log::debug!(target: "", "[{}:{}] {}", file!(), line!(), $fmt);
    };
    ($fmt:expr, $($arg:tt)*) => {
        log::debug!(target: "", "[{}:{}] {}", file!(), line!(), format_args!($fmt, $($arg)*));
    };
}
