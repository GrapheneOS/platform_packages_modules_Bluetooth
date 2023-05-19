use crate::init_flags::{
    get_log_level_for_tag, LOG_TAG_DEBUG, LOG_TAG_ERROR, LOG_TAG_FATAL, LOG_TAG_INFO,
    LOG_TAG_NOTICE, LOG_TAG_VERBOSE, LOG_TAG_WARN,
};

fn get_log_level() -> log::Level {
    match get_log_level_for_tag("bluetooth_core") {
        LOG_TAG_FATAL => log::Level::Error,
        LOG_TAG_ERROR => log::Level::Error,
        LOG_TAG_WARN => log::Level::Warn,
        LOG_TAG_NOTICE => log::Level::Info,
        LOG_TAG_INFO => log::Level::Info,
        LOG_TAG_DEBUG => log::Level::Debug,
        LOG_TAG_VERBOSE => log::Level::Trace,
        _ => log::Level::Info, // default level
    }
}

/// Inits logging for Android
#[cfg(target_os = "android")]
pub fn init_logging() {
    android_logger::init_once(
        android_logger::Config::default().with_tag("bt").with_min_level(get_log_level()),
    );
    log::set_max_level(get_log_level().to_level_filter())
}

/// Inits logging for host
#[cfg(not(target_os = "android"))]
pub fn init_logging() {
    env_logger::Builder::new()
        .filter(None, get_log_level().to_level_filter())
        .parse_default_env()
        .try_init()
        .ok();
    log::set_max_level(get_log_level().to_level_filter())
}
