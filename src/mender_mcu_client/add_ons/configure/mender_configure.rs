use crate::log_error;
use crate::mender_mcu_client::core::{
    mender_client,
    mender_utils::{KeyStore, MenderResult, MenderStatus},
};
use crate::mender_mcu_client::platform::scheduler::mender_scheduler::{
    self, MenderFuture, MenderSchedulerWorkContext,
};
use crate::mender_mcu_client::platform::storage::mender_storage;
use alloc::boxed::Box;
use alloc::string::String;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use heapless::FnvIndexMap;

// Constants
const CONFIG_MENDER_CLIENT_CONFIGURE_REFRESH_INTERVAL: u32 = 28800;

pub struct MenderConfigureConfig {
    pub refresh_interval: u32,
}

pub struct MenderConfigureCallbacks {
    pub config_updated: Option<fn(&KeyStore)>,
}

// Global static variables
static MENDER_CONFIGURE_CONFIG: Mutex<CriticalSectionRawMutex, Option<MenderConfigureConfig>> =
    Mutex::new(None);
static MENDER_CONFIGURE_CALLBACKS: Mutex<
    CriticalSectionRawMutex,
    Option<MenderConfigureCallbacks>,
> = Mutex::new(None);
static MENDER_CONFIGURE_KEYSTORE: Mutex<CriticalSectionRawMutex, Option<KeyStore>> =
    Mutex::new(None);

#[allow(dead_code)]
static MENDER_CONFIGURE_ARTIFACT_NAME: Mutex<CriticalSectionRawMutex, Option<String>> =
    Mutex::new(None);
static MENDER_CONFIGURE_WORK_HANDLE: Mutex<
    CriticalSectionRawMutex,
    Option<MenderSchedulerWorkContext>,
> = Mutex::new(None);

#[allow(dead_code)]
pub async fn mender_configure_init(
    config: Option<&MenderConfigureConfig>,
    callbacks: Option<&MenderConfigureCallbacks>,
) -> MenderResult<()> {
    // Save configuration
    let mut conf = MENDER_CONFIGURE_CONFIG.lock().await;
    *conf = Some(MenderConfigureConfig {
        refresh_interval: if let Some(cfg) = config {
            cfg.refresh_interval
        } else {
            CONFIG_MENDER_CLIENT_CONFIGURE_REFRESH_INTERVAL
        },
    });

    // Save callbacks
    if let Some(cbs) = callbacks {
        let mut callbacks_lock = MENDER_CONFIGURE_CALLBACKS.lock().await;
        *callbacks_lock = Some(MenderConfigureCallbacks {
            config_updated: cbs.config_updated,
        });
    }

    // Try to retrieve device configuration from storage
    if let Ok((_, device_config)) = mender_storage::mender_storage_get_device_config().await {
        // Parse and set configuration
        if let Ok((config_data, _)) = serde_json_core::de::from_str::<KeyStore>(&device_config) {
            let mut keystore = MENDER_CONFIGURE_KEYSTORE.lock().await;
            *keystore = Some(config_data);
        }
    }
    // TODO: for Storage

    // Create work
    let mut work_handle = MENDER_CONFIGURE_WORK_HANDLE.lock().await;
    match mender_scheduler::mender_scheduler_work_create(
        mender_configure_work,
        conf.as_ref().unwrap().refresh_interval,
        "mender_configure",
    ) {
        Ok(handle) => {
            *work_handle = Some(handle);
            Ok((MenderStatus::Ok, ()))
        }
        Err(_) => {
            log_error!("Unable to create configure work");
            Err(MenderStatus::Failed)
        }
    }
}

fn mender_configure_work() -> MenderFuture {
    Box::pin(async {
        match mender_configure_work_function().await {
            Ok(_) => Ok(()), // Discard the status, just return success
            Err(_) => Err("Configure work failed"),
        }
    })
}

async fn mender_configure_work_function() -> MenderResult<()> {
    let keystore = MENDER_CONFIGURE_KEYSTORE.lock().await;

    // Request access to the network
    if mender_client::mender_client_network_connect()
        .await
        .is_err()
    {
        log_error!("Requesting access to the network failed");
        return Err(MenderStatus::Failed);
    }

    #[cfg(not(feature = "mender_client_configure_storage"))]
    {
        // Download configuration
        match super::mender_configure_api::mender_configure_api_download_configuration_data().await
        {
            Ok(configuration) => {
                // Update device configuration
                let mut keystore = MENDER_CONFIGURE_KEYSTORE.lock().await;
                *keystore = Some(configuration.1); // Extract the KeyStore (second element) from the tuple

                // Invoke the update callback
                if let Some(callbacks) = MENDER_CONFIGURE_CALLBACKS.lock().await.as_ref() {
                    if let Some(update_fn) = callbacks.config_updated {
                        if let Some(config) = keystore.as_ref() {
                            update_fn(config);
                        }
                    }
                }
            }
            Err(_) => {
                log_error!("Unable to get configuration data");
            }
        }
    }

    // Publish configuration if available
    if let Some(config) = keystore.as_ref() {
        if super::mender_configure_api::mender_configure_api_publish_configuration_data(config)
            .await
            .is_err()
        {
            log_error!("Unable to publish configuration data");
        }
    }

    // Release access to the network
    mender_client::mender_client_network_release().await?;

    Ok((MenderStatus::Ok, ()))
}

#[allow(dead_code)]
pub async fn mender_configure_activate() -> MenderResult<()> {
    let mut work_handle = MENDER_CONFIGURE_WORK_HANDLE.lock().await;
    if let Some(handle) = work_handle.as_mut() {
        mender_scheduler::mender_scheduler_work_activate(handle)
            .await
            .map(|()| (MenderStatus::Ok, ()))
            .map_err(|_| {
                log_error!("Unable to activate configure work");
                MenderStatus::Failed
            })
    } else {
        Err(MenderStatus::Failed)
    }
}

#[allow(dead_code)]
pub async fn mender_configure_deactivate() -> MenderResult<()> {
    let mut work_handle = MENDER_CONFIGURE_WORK_HANDLE.lock().await;
    if let Some(handle) = work_handle.as_mut() {
        mender_scheduler::mender_scheduler_work_deactivate(handle)
            .await
            .map_err(|_| {
                log_error!("Unable to deactivate configure work");
                MenderStatus::Failed
            })?;
    }
    Ok((MenderStatus::Ok, ()))
}

#[allow(dead_code)]
pub async fn mender_configure_execute() -> MenderResult<()> {
    let mut work_handle = MENDER_CONFIGURE_WORK_HANDLE.lock().await;
    if let Some(handle) = work_handle.as_mut() {
        mender_scheduler::mender_scheduler_work_execute(handle)
            .await
            .map(|()| (MenderStatus::Ok, ()))
            .map_err(|_| {
                log_error!("Unable to trigger configure work");
                MenderStatus::Failed
            })
    } else {
        Err(MenderStatus::Failed)
    }
}

// pub async fn mender_configure_get() -> MenderResult<KeyStore> {
//     // Get the configuration from keystore
//     let keystore = MENDER_CONFIGURE_KEYSTORE.lock().await;

//     match keystore.as_ref() {
//         Some(config) => Ok((MenderStatus::Ok, config.clone())),
//         None => {
//             log_error!("No configuration available");
//             Err(MenderStatus::Failed)
//         }
//     }
// }

// pub async fn mender_configure_set(configuration: &KeyStore) -> MenderResult<()> {
//     let mut keystore = MENDER_CONFIGURE_KEYSTORE.lock().await;

//     // Update configuration
//     *keystore = Some(configuration.clone());

//     #[cfg(feature = "mender_client_configure_storage")]
//     {
//         // Create device config JSON using FnvIndexMap
//         let device_config = {
//             // First serialize the configuration to a JSON string
//             let config_str =
//                 serde_json_core::ser::to_string::<_, 1024>(configuration).map_err(|_| {
//                     log_error!("Unable to serialize configuration");
//                     MenderStatus::Failed
//                 })?;

//             // Get artifact name with extended lifetime
//             let artifact_name_lock = MENDER_CONFIGURE_ARTIFACT_NAME.lock().await;

//             let mut map: FnvIndexMap<&str, &str, 16> = FnvIndexMap::new();
//             map.insert("config", &config_str)
//                 .map_err(|_| MenderStatus::Failed)?;

//             if let Some(artifact_name) = artifact_name_lock.as_ref() {
//                 map.insert("artifact_name", artifact_name)
//                     .map_err(|_| MenderStatus::Failed)?;
//             }

//             serde_json_core::ser::to_string::<_, 1024>(&map).map_err(|_| {
//                 log_error!("Unable to format device config");
//                 MenderStatus::Failed
//             })?
//         };

//         // Save to storage
//         if let Err(_) = mender_storage::mender_storage_set_device_config(&device_config).await {
//             log_error!("Unable to record configuration");
//             return Err(MenderStatus::Failed);
//         }
//     }

//     Ok((MenderStatus::Ok, ()))
// }

// pub async fn mender_configure_exit() -> MenderResult<()> {
//     // Delete mender configure work
//     let mut work_handle = MENDER_CONFIGURE_WORK_HANDLE.lock().await;
//     if let Some(handle) = work_handle.as_mut() {
//         mender_scheduler::mender_scheduler_work_delete(handle)
//             .await
//             .map_err(|_| {
//                 log_error!("Unable to delete configure work");
//                 MenderStatus::Failed
//             })?;
//     }
//     *work_handle = None;

//     // Release memory by setting all globals to None
//     let mut config = MENDER_CONFIGURE_CONFIG.lock().await;
//     *config = None;

//     let mut callbacks = MENDER_CONFIGURE_CALLBACKS.lock().await;
//     *callbacks = None;

//     let mut keystore = MENDER_CONFIGURE_KEYSTORE.lock().await;
//     *keystore = None;

//     let mut artifact_name = MENDER_CONFIGURE_ARTIFACT_NAME.lock().await;
//     *artifact_name = None;

//     Ok((MenderStatus::Ok, ()))
// }

#[allow(dead_code)]
pub async fn mender_configure_download_artifact_callback(
    // _id: &str,
    artifact_name: &str,
    // _type: &str,
    meta_data: Option<&str>,
    // _filename: &str,
    // _size: usize,
    // _data: &[u8],
    // _index: usize,
    // _length: usize,
) -> MenderResult<()> {
    use crate::mender_mcu_client::platform::storage::mender_storage;

    if let Some(config_data) = meta_data {
        // Create device config using FnvIndexMap
        let mut config_map: FnvIndexMap<&str, &str, 16> = FnvIndexMap::new();
        config_map
            .insert("artifact_name", artifact_name)
            .map_err(|_| MenderStatus::Failed)?;
        config_map
            .insert("config", config_data)
            .map_err(|_| MenderStatus::Failed)?;

        // Convert to JSON string
        let device_config =
            serde_json_core::ser::to_string::<_, 1024>(&config_map).map_err(|_| {
                log_error!("Unable to format device config");
                MenderStatus::Failed
            })?;

        // Save to storage
        mender_storage::mender_storage_set_device_config(&device_config).await?;
    } else {
        // Delete configuration if no meta_data
        mender_storage::mender_storage_delete_device_config().await?;
    }

    Ok((MenderStatus::Ok, ()))
}
