use crate::mender_mcu_client::core::mender_utils::{MenderResult, MenderStatus};
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::str;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embedded_storage::{ReadStorage, Storage};
use esp_storage::FlashStorage;
use esp_storage::FlashStorageError;

// Partition base address and size
const KEY_DATA_BASE_ADDR: u32 = 0x370000;

// Section offsets
const PRIVATE_KEY_ADDR: u32 = KEY_DATA_BASE_ADDR;
const PUBLIC_KEY_ADDR: u32 = PRIVATE_KEY_ADDR + 0xC00;
const DEPLOYMENT_DATA_ADDR: u32 = PUBLIC_KEY_ADDR + 0xC00;
const DEVICE_CONFIG_ADDR: u32 = DEPLOYMENT_DATA_ADDR + 0xC00;

// Size constants
const MAX_KEY_SIZE: usize = 3072;
const MAX_DATA_SIZE: usize = 2048;

static MENDER_STORAGE: Mutex<CriticalSectionRawMutex, Option<FlashStorage>> = Mutex::new(None);

impl From<FlashStorageError> for MenderStatus {
    fn from(_: FlashStorageError) -> Self {
        MenderStatus::Failed
    }
}

// Public interface functions
pub async fn mender_storage_init() -> MenderResult<()> {
    let storage = FlashStorage::new();
    let mut conf = MENDER_STORAGE.lock().await;
    *conf = Some(storage);
    Ok((MenderStatus::Ok, ()))
}

pub async fn mender_storage_get_authentication_keys() -> MenderResult<(Vec<u8>, Vec<u8>)> {
    log_info!("mender_storage_get_authentication_keys");
    let mut storage = MENDER_STORAGE.lock().await;
    if let Some(storage) = storage.as_mut() {
        // Read private key length
        let mut priv_len_bytes = [0u8; 4];
        storage.read(PRIVATE_KEY_ADDR, &mut priv_len_bytes)?;
        let priv_len = u32::from_le_bytes(priv_len_bytes) as usize;

        // Read public key length
        let mut pub_len_bytes = [0u8; 4];
        storage.read(PUBLIC_KEY_ADDR, &mut pub_len_bytes)?;
        let pub_len = u32::from_le_bytes(pub_len_bytes) as usize;

        // Validate sizes
        if priv_len > MAX_KEY_SIZE || pub_len > MAX_KEY_SIZE {
            log_error!("Stored key size too large");
            return Err(MenderStatus::Failed);
        } else if priv_len == 0 || pub_len == 0 {
            log_error!("No authentication keys found");
            return Err(MenderStatus::NotFound);
        }

        // Read keys
        let mut private_key = vec![0u8; priv_len];
        let mut public_key = vec![0u8; pub_len];

        storage.read(PRIVATE_KEY_ADDR + 4, &mut private_key)?;
        storage.read(PUBLIC_KEY_ADDR + 4, &mut public_key)?;

        log_info!("Authentication keys retrieved successfully");
        Ok((MenderStatus::Ok, (private_key, public_key)))
    } else {
        log_error!("Failed to get authentication keys");
        Err(MenderStatus::Failed)
    }
}

pub async fn mender_storage_set_authentication_keys(
    private_key: &[u8],
    public_key: &[u8],
) -> MenderResult<()> {
    log_info!("Setting authentication keys");
    let mut storage = MENDER_STORAGE.lock().await;
    if let Some(storage) = storage.as_mut() {
        if private_key.len() > MAX_KEY_SIZE || public_key.len() > MAX_KEY_SIZE {
            log_error!("Key size too large");
            return Err(MenderStatus::Failed);
        }

        let priv_len = private_key.len() as u32;
        storage.write(PRIVATE_KEY_ADDR, &priv_len.to_le_bytes())?;
        storage.write(PRIVATE_KEY_ADDR + 4, private_key)?;

        let pub_len = public_key.len() as u32;
        storage.write(PUBLIC_KEY_ADDR, &pub_len.to_le_bytes())?;
        storage.write(PUBLIC_KEY_ADDR + 4, public_key)?;

        log_info!("Authentication keys set successfully");
        Ok((MenderStatus::Ok, ()))
    } else {
        log_error!("Failed to set authentication keys");
        Err(MenderStatus::Failed)
    }
}

pub async fn mender_storage_delete_authentication_keys() -> MenderResult<()> {
    let mut storage = MENDER_STORAGE.lock().await;
    if let Some(storage) = storage.as_mut() {
        storage.write(PRIVATE_KEY_ADDR, &[0u8; 4])?;
        storage.write(PUBLIC_KEY_ADDR, &[0u8; 4])?;
        log_info!("Authentication keys deleted successfully");
        Ok((MenderStatus::Ok, ()))
    } else {
        log_error!("Failed to delete authentication keys");
        Err(MenderStatus::Failed)
    }
}

pub async fn mender_storage_set_deployment_data(deployment_data: &str) -> MenderResult<()> {
    log_info!("mender_storage_set_deployment_data: {}", deployment_data);
    let mut storage = MENDER_STORAGE.lock().await;
    if let Some(storage) = storage.as_mut() {
        let data = deployment_data.as_bytes();
        if data.len() > MAX_DATA_SIZE {
            log_error!("Deployment data too large");
            return Err(MenderStatus::Failed);
        }

        let len = data.len() as u32;
        storage.write(DEPLOYMENT_DATA_ADDR, &len.to_le_bytes())?;
        storage.write(DEPLOYMENT_DATA_ADDR + 4, data)?;
        log_info!("Deployment data set successfully");
        Ok((MenderStatus::Ok, ()))
    } else {
        log_error!("Failed to set deployment data");
        Err(MenderStatus::Failed)
    }
}

pub async fn mender_storage_get_deployment_data() -> MenderResult<String> {
    log_info!("mender_storage_get_deployment_data");
    let mut storage = MENDER_STORAGE.lock().await;
    if let Some(storage) = storage.as_mut() {
        let mut len_bytes = [0u8; 4];
        storage.read(DEPLOYMENT_DATA_ADDR, &mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        if len == 0 || len > MAX_DATA_SIZE {
            log_warn!("Deployment data not found");
            return Err(MenderStatus::NotFound);
        }

        let mut data = vec![0u8; len];
        storage.read(DEPLOYMENT_DATA_ADDR + 4, &mut data)?;

        String::from_utf8(data)
            .map_err(|_| {
                log_error!("Invalid UTF-8 in deployment data");
                MenderStatus::Failed
            })
            .map(|s| (MenderStatus::Ok, s))
    } else {
        log_error!("Failed to get deployment data");
        Err(MenderStatus::Failed)
    }
}

pub async fn mender_storage_delete_deployment_data() -> MenderResult<()> {
    let mut storage = MENDER_STORAGE.lock().await;
    if let Some(storage) = storage.as_mut() {
        storage.write(DEPLOYMENT_DATA_ADDR, &[0u8; 4])?;
        log_info!("Deployment data deleted successfully");
        Ok((MenderStatus::Ok, ()))
    } else {
        log_error!("Failed to delete deployment data");
        Err(MenderStatus::Failed)
    }
}

#[allow(dead_code)]
pub async fn mender_storage_exit() -> MenderResult<()> {
    let mut storage = MENDER_STORAGE.lock().await;
    *storage = None;
    Ok((MenderStatus::Ok, ()))
}

pub async fn mender_storage_set_device_config(device_config: &str) -> MenderResult<()> {
    log_info!("Setting device configuration");
    let mut storage = MENDER_STORAGE.lock().await;
    if let Some(storage) = storage.as_mut() {
        let data = device_config.as_bytes();
        if data.len() > MAX_DATA_SIZE {
            log_error!("Device config too large");
            return Err(MenderStatus::Failed);
        }

        let len = data.len() as u32;
        storage.write(DEVICE_CONFIG_ADDR, &len.to_le_bytes())?;
        storage.write(DEVICE_CONFIG_ADDR + 4, data)?;
        log_info!("Device configuration set successfully");
        Ok((MenderStatus::Ok, ()))
    } else {
        log_error!("Failed to set device configuration");
        Err(MenderStatus::Failed)
    }
}

pub async fn mender_storage_get_device_config() -> MenderResult<String> {
    log_info!("Getting device configuration");
    let mut storage = MENDER_STORAGE.lock().await;
    if let Some(storage) = storage.as_mut() {
        let mut len_bytes = [0u8; 4];
        storage.read(DEVICE_CONFIG_ADDR, &mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        if len == 0 || len > MAX_DATA_SIZE {
            log_error!("Device config not found");
            return Err(MenderStatus::NotFound);
        }

        let mut data = vec![0u8; len];
        storage.read(DEVICE_CONFIG_ADDR + 4, &mut data)?;

        String::from_utf8(data)
            .map_err(|_| {
                log_error!("Invalid UTF-8 in device config");
                MenderStatus::Failed
            })
            .map(|s| (MenderStatus::Ok, s))
    } else {
        log_error!("Failed to get device configuration");
        Err(MenderStatus::Failed)
    }
}

pub async fn mender_storage_delete_device_config() -> MenderResult<()> {
    log_info!("Deleting device configuration");
    let mut storage = MENDER_STORAGE.lock().await;
    if let Some(storage) = storage.as_mut() {
        storage.write(DEVICE_CONFIG_ADDR, &[0u8; 4])?;
        log_info!("Device configuration deleted successfully");
        Ok((MenderStatus::Ok, ()))
    } else {
        log_error!("Failed to delete device configuration");
        Err(MenderStatus::Failed)
    }
}
