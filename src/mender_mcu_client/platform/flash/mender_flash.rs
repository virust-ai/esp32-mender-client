use crate::alloc::string::ToString;
use crate::external::esp_hal_ota::Ota;
use crate::external::esp_hal_ota::OtaImgState;
use crate::mender_mcu_client::core::mender_utils::MenderResult;
use crate::mender_mcu_client::core::mender_utils::MenderStatus;
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::string::String;
use core::fmt;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use esp_storage::FlashStorage;

// Mock flash state
static FLASH_HANDLE: Mutex<CriticalSectionRawMutex, Option<FlashHandle>> = Mutex::new(None);

struct FlashHandle {
    filename: String,
    size: u32,
    current_position: u32,
    ota: Ota<FlashStorage>,
}

// Implement custom Debug that skips the ota field
impl fmt::Debug for FlashHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlashHandle")
            .field("filename", &self.filename)
            .field("size", &self.size)
            .field("current_position", &self.current_position)
            .finish()
    }
}

pub async fn mender_flash_open(filename: &str, size: u32, chksum: &[u8]) -> MenderResult<()> {
    log_info!(
        "mender_flash_open, filename: {:?}, size: {}",
        filename,
        size
    );
    let mut handle = FLASH_HANDLE.lock().await;

    // Check if flash is already open
    if handle.is_some() {
        log_error!("Flash already open");
        return Err(MenderStatus::Failed);
    }

    // Initialize OTA
    let mut ota = match Ota::new(FlashStorage::new()) {
        Ok(ota) => ota,
        Err(e) => {
            log_error!("Failed to create OTA instance, error: {:?}", e);
            return Err(MenderStatus::Failed);
        }
    };

    // Begin OTA update
    // Note: target_crc is set to 0 initially, it will be updated later if needed
    if let Err(e) = ota.ota_begin(size, chksum) {
        log_error!("Failed to begin OTA, error: {:?}", e);
        return Err(MenderStatus::Failed);
    }

    // Create new flash handle
    *handle = Some(FlashHandle {
        filename: filename.to_string(),
        size,
        current_position: 0,
        ota,
    });

    log_info!("Opened flash for, filename: {}, size: {}", filename, size);
    Ok((MenderStatus::Ok, ()))
}

pub async fn mender_flash_write(data: &[u8], index: u32, length: u32) -> MenderResult<()> {
    log_info!("mender_flash_write, index: {}, length: {}", index, length);
    let mut handle = FLASH_HANDLE.lock().await;

    let flash = handle.as_mut().ok_or_else(|| {
        log_error!("Flash not open");
        MenderStatus::Failed
    })?;

    // Validate write position
    if index != flash.current_position {
        log_error!("Invalid write position: {}", flash.current_position);
        return Err(MenderStatus::Failed);
    }

    // Validate write size
    if index + length > flash.size {
        log_error!("Write exceeds flash size");
        return Err(MenderStatus::Failed);
    }

    // Write data using OTA
    if let Err(e) = flash.ota.ota_write_chunk(data, length) {
        log_error!("Failed to write OTA chunk, error: {:?}", e);
        return Err(MenderStatus::Failed);
    }

    // Update position
    flash.current_position += length;

    Ok((MenderStatus::Ok, ()))
}

pub async fn mender_flash_close() -> MenderResult<()> {
    log_info!("mender_flash_close");
    let mut handle = FLASH_HANDLE.lock().await;

    let flash = handle.as_mut().ok_or_else(|| {
        log_error!("Flash not open");
        MenderStatus::Failed
    })?;

    // Verify all data was written
    if flash.current_position != flash.size {
        log_error!(
            "Incomplete write - current_position: {}, size: {}",
            flash.current_position,
            flash.size
        );
        return Err(MenderStatus::Failed);
    }

    log_info!(
        "Closing flash. Wrote - current_position: {}, filename: {}",
        flash.current_position,
        flash.filename
    );

    // Flush and finalize OTA
    // verify=false because we'll verify later, reboot=true to apply the update
    if let Err(e) = flash.ota.ota_flush(true) {
        log_error!("Failed to flush OTA, error: {:?}", e);
        return Err(MenderStatus::Failed);
    }

    Ok((MenderStatus::Ok, ()))
}

pub async fn mender_flash_abort_deployment() -> MenderResult<()> {
    log_info!("mender_flash_abort_deployment");
    let mut handle = FLASH_HANDLE.lock().await;

    if let Some(flash) = handle.as_mut() {
        if let Err(e) = flash.ota.ota_abort() {
            log_error!("Failed to abort OTA: {:?}", e);
        }
        // No need to explicitly abort OTA - it will be cleaned up when the handle is dropped
        *handle = None;
    }

    Ok((MenderStatus::Ok, ()))
}

pub async fn mender_flash_set_pending_image() -> MenderResult<()> {
    log_info!("mender_flash_set_pending_image");
    // The OTA update is already set to pending during flash_close
    let mut handle = FLASH_HANDLE.lock().await;

    if let Some(flash) = handle.as_mut() {
        // Verify all data was written
        if flash.current_position != flash.size {
            log_error!(
                "Incomplete write - current_position: {}, size: {}",
                flash.current_position,
                flash.size
            );
            return Err(MenderStatus::Failed);
        }

        if let Err(e) = flash.ota.ota_set_pending_image(true) {
            log_error!("Failed to set pending image, {:?}", e);
        }
        *handle = None;
    }
    Ok((MenderStatus::Ok, ()))
}

pub fn mender_flash_confirm_image() -> MenderResult<()> {
    log_info!("mender_flash_confirm_image");

    let mut ota = match Ota::new(FlashStorage::new()) {
        Ok(ota) => ota,
        Err(e) => {
            log_error!("Failed to create OTA instance, {:?}", e);
            return Err(MenderStatus::Failed);
        }
    };

    if let Err(e) = ota.ota_mark_app_valid() {
        log_error!("Failed to mark app valid, {:?}", e);
        return Err(MenderStatus::Failed);
    }

    Ok((MenderStatus::Ok, ()))
}

pub fn mender_flash_is_image_confirmed() -> bool {
    log_info!("mender_flash_is_image_confirmed");
    let mut ota = match Ota::new(FlashStorage::new()) {
        Ok(ota) => ota,
        Err(e) => {
            log_error!("Failed to create OTA instance, {:?}", e);
            return false;
        }
    };

    let image_state = ota.get_ota_image_state();
    matches!(image_state, Ok(OtaImgState::EspOtaImgValid))
}
