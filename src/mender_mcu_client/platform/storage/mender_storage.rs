use crate::mender_mcu_client::core::mender_utils::{MenderResult, MenderStatus};
use crate::mender_mcu_client::mender_prj_config::{TLS_PRIVATE_KEY_LENGTH, TLS_PUBLIC_KEY_LENGTH};
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

const MAX_DATA_SIZE: u32 = 1024;

const PART_OFFSET: u32 = 0x8000;
const PART_SIZE: u32 = 0xc00;
const FIRST_OTA_PART_SUBTYPE: u8 = 2;

#[derive(Debug)]
pub struct FlashKeyInfo {
    pub privatekey_offset: u32,
    pub publickey_offset: u32,
    pub deployment_data_offset: u32,
    pub device_config_offset: u32,
    pub flashkey_size: u32,
}

pub struct FlashKey<S>
where
    S: ReadStorage + Storage,
{
    flash: S,

    pinfo: FlashKeyInfo,
}

impl<S> FlashKey<S>
where
    S: ReadStorage + Storage,
{
    pub fn new(mut flash: S) -> MenderResult<Self> {
        let (_, pinfo) = Self::read_keydata_partitions(&mut flash)?;

        // Return with MenderStatus::Ok
        Ok((MenderStatus::Ok, FlashKey { flash, pinfo }))
    }

    fn read_keydata_partitions(flash: &mut S) -> MenderResult<FlashKeyInfo> {
        let mut tmp_pinfo = FlashKeyInfo {
            privatekey_offset: 0,
            publickey_offset: 0,
            deployment_data_offset: 0,
            device_config_offset: 0,
            flashkey_size: 0,
        };

        let mut bytes = [0xFF; 32];
        for read_offset in (0..PART_SIZE).step_by(32) {
            _ = flash.read(PART_OFFSET + read_offset, &mut bytes);
            if bytes == [0xFF; 32] {
                break;
            }

            let magic = &bytes[0..2];
            if magic != [0xAA, 0x50] {
                continue;
            }

            let p_type = &bytes[2];
            let p_subtype = &bytes[3];
            let p_offset = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            let p_size = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            let p_name = core::str::from_utf8(&bytes[12..28]).unwrap();
            let p_flags = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
            log_info!(
                "{:?} {} {} {} {} {} {}",
                magic,
                p_type,
                p_subtype,
                p_offset,
                p_size,
                p_name,
                p_flags
            );

            if *p_type == 1 && *p_subtype == FIRST_OTA_PART_SUBTYPE {
                tmp_pinfo.privatekey_offset = p_offset;
                tmp_pinfo.flashkey_size = p_size;
            }
        }

        tmp_pinfo.publickey_offset = tmp_pinfo.privatekey_offset + TLS_PRIVATE_KEY_LENGTH;
        tmp_pinfo.deployment_data_offset = tmp_pinfo.publickey_offset + TLS_PUBLIC_KEY_LENGTH;
        tmp_pinfo.device_config_offset = tmp_pinfo.deployment_data_offset + MAX_DATA_SIZE;

        log_debug!("FlashKeyInfo: {:?}", tmp_pinfo);

        if (tmp_pinfo.privatekey_offset + tmp_pinfo.flashkey_size)
            >= (tmp_pinfo.device_config_offset + MAX_DATA_SIZE)
        {
            // Return with MenderStatus::Ok
            Ok((MenderStatus::Ok, tmp_pinfo))
        } else {
            log_error!("FlashKeyInfo size is not valid");
            Err(MenderStatus::Failed)
        }
    }
}

static MENDER_STORAGE: Mutex<CriticalSectionRawMutex, Option<FlashKey<FlashStorage>>> =
    Mutex::new(None);

impl From<FlashStorageError> for MenderStatus {
    fn from(_: FlashStorageError) -> Self {
        MenderStatus::Failed
    }
}

// Public interface functions
pub async fn mender_storage_init() -> MenderResult<()> {
    let (_, flashkey) = match FlashKey::new(FlashStorage::new()) {
        Ok(result) => result,
        Err(e) => {
            log_error!("Failed to create FlashKey instance, error: {:?}", e);
            return Err(MenderStatus::Failed);
        }
    };

    let mut conf = MENDER_STORAGE.lock().await;
    *conf = Some(flashkey);
    Ok((MenderStatus::Ok, ()))
}

pub async fn mender_storage_get_authentication_keys() -> MenderResult<(Vec<u8>, Vec<u8>)> {
    log_info!("mender_storage_get_authentication_keys");
    let mut storage = MENDER_STORAGE.lock().await;
    if let Some(storage) = storage.as_mut() {
        // Read private key length
        let mut priv_len_bytes = [0u8; 4];
        storage
            .flash
            .read(storage.pinfo.privatekey_offset, &mut priv_len_bytes)?;
        let priv_len = u32::from_le_bytes(priv_len_bytes);

        // Read public key length
        let mut pub_len_bytes = [0u8; 4];
        storage
            .flash
            .read(storage.pinfo.publickey_offset, &mut pub_len_bytes)?;
        let pub_len = u32::from_le_bytes(pub_len_bytes);

        // Validate sizes
        if priv_len > TLS_PRIVATE_KEY_LENGTH || pub_len > TLS_PUBLIC_KEY_LENGTH {
            log_error!("Stored key size too large");
            return Err(MenderStatus::Failed);
        } else if priv_len == 0 || pub_len == 0 {
            log_error!("No authentication keys found");
            return Err(MenderStatus::NotFound);
        }

        // Read keys
        let mut private_key = vec![0u8; priv_len as usize];
        let mut public_key = vec![0u8; pub_len as usize];

        storage
            .flash
            .read(storage.pinfo.privatekey_offset + 4, &mut private_key)?;
        storage
            .flash
            .read(storage.pinfo.publickey_offset + 4, &mut public_key)?;

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
        if private_key.len() > TLS_PRIVATE_KEY_LENGTH as usize
            || public_key.len() > TLS_PUBLIC_KEY_LENGTH as usize
        {
            log_error!("Key size too large");
            return Err(MenderStatus::Failed);
        }

        let priv_len = private_key.len() as u32;
        storage
            .flash
            .write(storage.pinfo.privatekey_offset, &priv_len.to_le_bytes())?;
        storage
            .flash
            .write(storage.pinfo.privatekey_offset + 4, private_key)?;

        let pub_len = public_key.len() as u32;
        storage
            .flash
            .write(storage.pinfo.publickey_offset, &pub_len.to_le_bytes())?;
        storage
            .flash
            .write(storage.pinfo.publickey_offset + 4, public_key)?;

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
        storage
            .flash
            .write(storage.pinfo.privatekey_offset, &[0u8; 4])?;
        storage
            .flash
            .write(storage.pinfo.publickey_offset, &[0u8; 4])?;
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
        if data.len() > MAX_DATA_SIZE as usize {
            log_error!("Deployment data too large");
            return Err(MenderStatus::Failed);
        }

        let len = data.len() as u32;
        storage
            .flash
            .write(storage.pinfo.deployment_data_offset, &len.to_le_bytes())?;
        storage
            .flash
            .write(storage.pinfo.deployment_data_offset + 4, data)?;
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
        storage
            .flash
            .read(storage.pinfo.deployment_data_offset, &mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes);

        if len == 0 || len > MAX_DATA_SIZE {
            log_warn!("Deployment data not found");
            return Err(MenderStatus::NotFound);
        }

        let mut data = vec![0u8; len as usize];
        storage
            .flash
            .read(storage.pinfo.deployment_data_offset + 4, &mut data)?;

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
        storage
            .flash
            .write(storage.pinfo.deployment_data_offset, &[0u8; 4])?;
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
        if data.len() > MAX_DATA_SIZE as usize {
            log_error!("Device config too large");
            return Err(MenderStatus::Failed);
        }

        let len = data.len() as u32;
        storage
            .flash
            .write(storage.pinfo.device_config_offset, &len.to_le_bytes())?;
        storage
            .flash
            .write(storage.pinfo.device_config_offset + 4, data)?;
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
        storage
            .flash
            .read(storage.pinfo.device_config_offset, &mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes);

        if len == 0 || len > MAX_DATA_SIZE {
            log_error!("Device config not found");
            return Err(MenderStatus::NotFound);
        }

        let mut data = vec![0u8; len as usize];
        storage
            .flash
            .read(storage.pinfo.device_config_offset + 4, &mut data)?;

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
        storage
            .flash
            .write(storage.pinfo.device_config_offset, &[0u8; 4])?;
        log_info!("Device configuration deleted successfully");
        Ok((MenderStatus::Ok, ()))
    } else {
        log_error!("Failed to delete device configuration");
        Err(MenderStatus::Failed)
    }
}
