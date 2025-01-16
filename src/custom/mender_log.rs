use alloc::format;
use log::{self, Level};

/// Define log levels
pub const MENDER_LOG_LEVEL_ERR: u8 = 1;
pub const MENDER_LOG_LEVEL_WRN: u8 = 2;
pub const MENDER_LOG_LEVEL_INF: u8 = 3;
pub const MENDER_LOG_LEVEL_DBG: u8 = 4;

/// Set the configured log level
pub const CONFIG_MENDER_LOG_LEVEL: u8 = MENDER_LOG_LEVEL_DBG;

/// Core logging function that supports multiple parameters
pub fn log_with_level(
    level: u8,
    file: &str,
    line: u32,
    message: &str,
    params: &[(&str, &dyn core::fmt::Debug)],
) {
    if level > CONFIG_MENDER_LOG_LEVEL {
        return;
    }

    let mut log_message = format!("[{}:{}] {}", file, line, message);

    if !params.is_empty() {
        log_message.push_str(" {");
        for (i, (key, value)) in params.iter().enumerate() {
            if i > 0 {
                log_message.push_str(", ");
            }
            log_message.push_str(&format!("{}={:?}", key, value));
        }
        log_message.push('}');
    }

    match level {
        MENDER_LOG_LEVEL_ERR => log::error!("{}", log_message),
        MENDER_LOG_LEVEL_WRN => log::warn!("{}", log_message),
        MENDER_LOG_LEVEL_INF => log::info!("{}", log_message),
        MENDER_LOG_LEVEL_DBG => log::debug!("{}", log_message),
        _ => {}
    }
}

#[macro_export]
macro_rules! log_error {
    ($msg:expr) => {
        $crate::custom::mender_log::log_with_level(
            $crate::custom::mender_log::MENDER_LOG_LEVEL_ERR,
            file!(),
            line!(),
            $msg,
            &[]
        );
    };
    ($msg:expr, $($key:expr => $value:expr),+ $(,)?) => {
        $crate::custom::mender_log::log_with_level(
            $crate::custom::mender_log::MENDER_LOG_LEVEL_ERR,
            file!(),
            line!(),
            $msg,
            &[$( ($key, &$value) ),*]
        );
    };
}

#[macro_export]
macro_rules! log_warn {
    ($msg:expr) => {
        $crate::custom::mender_log::log_with_level(
            $crate::custom::mender_log::MENDER_LOG_LEVEL_WRN,
            file!(),
            line!(),
            $msg,
            &[]
        );
    };
    ($msg:expr, $($key:expr => $value:expr),+ $(,)?) => {
        $crate::custom::mender_log::log_with_level(
            $crate::custom::mender_log::MENDER_LOG_LEVEL_WRN,
            file!(),
            line!(),
            $msg,
            &[$( ($key, &$value) ),*]
        );
    };
}

#[macro_export]
macro_rules! log_info {
    ($msg:expr) => {
        $crate::custom::mender_log::log_with_level(
            $crate::custom::mender_log::MENDER_LOG_LEVEL_INF,
            file!(),
            line!(),
            $msg,
            &[]
        );
    };
    ($msg:expr, $($key:expr => $value:expr),+ $(,)?) => {
        $crate::custom::mender_log::log_with_level(
            $crate::custom::mender_log::MENDER_LOG_LEVEL_INF,
            file!(),
            line!(),
            $msg,
            &[$( ($key, &$value) ),*]
        );
    };
}

#[macro_export]
macro_rules! log_debug {
    ($msg:expr) => {
        $crate::custom::mender_log::log_with_level(
            $crate::custom::mender_log::MENDER_LOG_LEVEL_DBG,
            file!(),
            line!(),
            $msg,
            &[]
        );
    };
    ($msg:expr, $($key:expr => $value:expr),+ $(,)?) => {
        $crate::custom::mender_log::log_with_level(
            $crate::custom::mender_log::MENDER_LOG_LEVEL_DBG,
            file!(),
            line!(),
            $msg,
            &[$( ($key, &$value) ),*]
        );
    };
}
