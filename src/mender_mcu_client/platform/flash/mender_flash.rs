use crate::alloc::string::ToString;
use crate::mender_mcu_client::core::mender_utils::MenderError;
use crate::mender_mcu_client::core::mender_utils::MenderResult;
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::string::String;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;

// Mock flash state
static FLASH_HANDLE: Mutex<CriticalSectionRawMutex, Option<FlashHandle>> = Mutex::new(None);

#[derive(Debug)]
struct FlashHandle {
    filename: String,
    size: usize,
    current_position: usize,
}

pub async fn mender_flash_open(filename: &str, size: usize) -> MenderResult<()> {
    log_info!("mender_flash_open", "filename" => filename, "size" => size);
    let mut handle = FLASH_HANDLE.lock().await;

    // Check if flash is already open
    if handle.is_some() {
        log_error!("Flash already open");
        return Err(MenderError::Failed);
    }

    // Create new flash handle
    *handle = Some(FlashHandle {
        filename: filename.to_string(),
        size,
        current_position: 0,
    });

    log_info!("Opened flash for :", "filename" => filename, "size" => size);
    Ok(())
}

pub async fn mender_flash_write(data: &[u8], index: usize, length: usize) -> MenderResult<()> {
    log_info!("mender_flash_write", "data" => data, "index" => index, "length" => length);
    let mut handle = FLASH_HANDLE.lock().await;

    let flash = handle.as_mut().ok_or_else(|| {
        log_error!("Flash not open");
        MenderError::Failed
    })?;

    // Validate write position
    if index != flash.current_position {
        log_error!("Invalid write position", "flash.current_position" => flash.current_position, "index" => index);
        return Err(MenderError::Failed);
    }

    // Validate write size
    if index + length > flash.size {
        log_error!("Write exceeds flash size");
        return Err(MenderError::Failed);
    }

    // Update position
    flash.current_position += length;

    log_info!(
        "Writing to flash: ",
        "length" => length,
        "index" => index,
        "flash.filename" => flash.filename
    );

    Ok(())
}

pub async fn mender_flash_close() -> MenderResult<()> {
    log_info!("mender_flash_close");
    let mut handle = FLASH_HANDLE.lock().await;

    if handle.is_none() {
        log_error!("Flash not open");
        return Err(MenderError::Failed);
    }

    // Get the handle before clearing it
    let flash = handle.as_ref().unwrap();

    // Verify all data was written
    if flash.current_position != flash.size {
        log_error!(
            "Incomplete write: ",
            "flash.current_position" => flash.current_position,
            "flash.size" => flash.size
        );
        return Err(MenderError::Failed);
    }

    log_info!(
        "Closing flash. Wrote ",
        "flash.current_position" => flash.current_position,
        "flash.filename" => flash.filename
    );

    // Clear the handle
    *handle = None;

    Ok(())
}

pub async fn mender_flash_abort_deployment() -> MenderResult<()> {
    log_info!("mender_flash_abort_deployment");
    let mut handle = FLASH_HANDLE.lock().await;

    if handle.is_some() {
        log_info!("Aborting flash deployment");
        *handle = None;
    }

    Ok(())
}

pub async fn mender_flash_set_pending_image() -> MenderResult<()> {
    log_info!("mender_flash_set_pending_image");
    // Temporary mock implementation
    Ok(())
}
