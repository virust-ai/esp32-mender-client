extern crate alloc;
use crate::alloc::string::ToString;
use crate::mender_mcu_client::add_ons::mender_addon::{MenderAddon, MenderAddonInstance};
use crate::mender_mcu_client::core::mender_api;
use crate::mender_mcu_client::core::mender_api::{mender_api_init, MenderApiConfig};
use crate::mender_mcu_client::core::mender_utils::{
    DeploymentStatus, KeyStore, MenderError, MenderResult,
};
use crate::mender_mcu_client::platform::scheduler::mender_scheduler::{
    mender_scheduler_init, mender_scheduler_work_activate, mender_scheduler_work_create,
    mender_scheduler_work_deactivate, mender_scheduler_work_delete, MenderFuture,
    MenderSchedulerWorkContext,
};
use alloc::boxed::Box;
use alloc::string::String;
use core::pin::Pin;
use embassy_executor::Spawner;
use embassy_net::Stack;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use esp_hal::rng::Trng;
use heapless::{String as HString, Vec as HVec};
use serde::{Deserialize, Serialize};
use serde_json_core::de::from_str;

use crate::custom::mender_common::{MenderArtifactCallback, MenderCallback};
use crate::mender_mcu_client::platform::flash::mender_flash;
use crate::mender_mcu_client::platform::scheduler::mender_scheduler;
use crate::mender_mcu_client::platform::storage::mender_storage;
use crate::mender_mcu_client::platform::tls::mender_tls;

#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::vec::Vec;
use core::future::Future;

pub const CONFIG_MENDER_SERVER_HOST: &str = "https://mender.bluleap.ai";
pub const CONFIG_MENDER_AUTH_POLL_INTERVAL: i32 = 60; // default 600;
pub const CONFIG_MENDER_UPDATE_POLL_INTERVAL: i32 = 1800; // default 1800;
pub const CONFIG_MENDER_SERVER_TENANT_TOKEN: &str = "";

#[derive(Debug, Clone)]
pub struct MenderClientConfig {
    pub identity: KeyStore,
    pub artifact_name: String,
    pub device_type: String,
    pub host: String,
    pub tenant_token: Option<String>,
    pub authentication_poll_interval: i32,
    pub update_poll_interval: i32,
    pub recommissioning: bool,
}

impl MenderClientConfig {
    pub fn new(
        identity: KeyStore,
        artifact_name: &str,
        device_type: &str,
        host: &str,
        tenant_token: Option<&str>,
    ) -> Self {
        Self {
            identity,
            artifact_name: artifact_name.to_string(),
            device_type: device_type.to_string(),
            host: host.to_string(),
            tenant_token: tenant_token.map(|s| s.to_string()),
            authentication_poll_interval: 0,
            update_poll_interval: 0,
            recommissioning: false,
        }
    }

    pub fn with_host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    pub fn with_auth_interval(mut self, interval: i32) -> Self {
        self.authentication_poll_interval = interval;
        self
    }

    pub fn with_update_interval(mut self, interval: i32) -> Self {
        self.update_poll_interval = interval;
        self
    }

    pub fn with_recommissioning(mut self, recommissioning: bool) -> Self {
        self.recommissioning = recommissioning;
        self
    }
}

#[derive(Debug, Clone)]
pub struct MenderClientCallbacks {
    pub network_connect: fn() -> MenderResult<()>,
    pub network_release: fn() -> MenderResult<()>,
    pub authentication_success: fn() -> MenderResult<()>,
    pub authentication_failure: fn() -> MenderResult<()>,
    pub deployment_status: fn(status: DeploymentStatus, message: Option<&str>) -> MenderResult<()>,
    pub restart: fn() -> MenderResult<()>,
}

impl MenderClientCallbacks {
    pub fn new(
        network_connect: fn() -> MenderResult<()>,
        network_release: fn() -> MenderResult<()>,
        authentication_success: fn() -> MenderResult<()>,
        authentication_failure: fn() -> MenderResult<()>,
        deployment_status: fn(status: DeploymentStatus, message: Option<&str>) -> MenderResult<()>,
        restart: fn() -> MenderResult<()>,
    ) -> Self {
        Self {
            network_connect,
            network_release,
            authentication_success,
            authentication_failure,
            deployment_status,
            restart,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MenderClientState {
    MenderClientStateInitialization, // Perform initialization
    MenderClientStateAuthentication, // Perform authentication with the server
    MenderClientStateAuthenticated,  // Perform updates
}

static MENDER_CLIENT_NETWORK_COUNT: Mutex<CriticalSectionRawMutex, u8> = Mutex::new(0);

static MENDER_CLIENT_CONFIG: Mutex<CriticalSectionRawMutex, Option<MenderClientConfig>> =
    Mutex::new(None);

static MENDER_CLIENT_CALLBACKS: Mutex<CriticalSectionRawMutex, Option<MenderClientCallbacks>> =
    Mutex::new(None);

// Static client state
static MENDER_CLIENT_STATE: Mutex<CriticalSectionRawMutex, MenderClientState> =
    Mutex::new(MenderClientState::MenderClientStateInitialization);

// Add this with other static variables at the top
static MENDER_CLIENT_WORK: Mutex<CriticalSectionRawMutex, Option<MenderSchedulerWorkContext>> =
    Mutex::new(None);

// Static storage for addons - using () for both generic parameters
static MENDER_CLIENT_ADDONS: Mutex<CriticalSectionRawMutex, Vec<&'static dyn MenderAddon>> =
    Mutex::new(Vec::new());

// Constants and type definitions
const MAX_JSON_STRING_SIZE: usize = 128;
const MAX_JSON_ARRAY_SIZE: usize = 32;

// Define JSON-compatible data structure
#[derive(Serialize, Deserialize, Debug, Clone)]
struct DeploymentData {
    id: HString<MAX_JSON_STRING_SIZE>,
    artifact_name: HString<MAX_JSON_STRING_SIZE>,
    types: HVec<HString<MAX_JSON_STRING_SIZE>, MAX_JSON_ARRAY_SIZE>,
}
// Static storage
static MENDER_CLIENT_DEPLOYMENT_DATA: Mutex<CriticalSectionRawMutex, Option<DeploymentData>> =
    Mutex::new(None);

pub struct StaticTrng(&'static mut Trng<'static>);
impl StaticTrng {
    pub fn get_trng(&mut self) -> &mut Trng<'static> {
        self.0
    }
}

unsafe impl Send for StaticTrng {}
unsafe impl Sync for StaticTrng {}
// Add this with other static variables at the top
pub static MENDER_CLIENT_RNG: Mutex<CriticalSectionRawMutex, Option<StaticTrng>> = Mutex::new(None);

static MENDER_CLIENT_DEPLOYMENT_NEEDS_SET_PENDING_IMAGE: Mutex<CriticalSectionRawMutex, bool> =
    Mutex::new(false);
static MENDER_CLIENT_DEPLOYMENT_NEEDS_RESTART: Mutex<CriticalSectionRawMutex, bool> =
    Mutex::new(false);

#[derive(Clone)]
pub struct ArtifactTypeHandler {
    pub type_name: HString<32>,
    pub callback: &'static dyn MenderArtifactCallback,
    pub needs_restart: bool,
    pub artifact_name: HString<32>,
}

static MENDER_CLIENT_ARTIFACT_TYPES: Mutex<
    CriticalSectionRawMutex,
    Option<HVec<ArtifactTypeHandler, MAX_JSON_ARRAY_SIZE>>,
> = Mutex::new(None);

pub struct CryptoRng<'a>(Trng<'a>);

impl<'a> CryptoRng<'a> {
    pub fn new(rng: Trng<'a>) -> Self {
        CryptoRng(rng)
    }
}

// Make FlashCallback static
static FLASH_CALLBACK: FlashCallback = FlashCallback;

pub struct FlashCallback;

impl MenderArtifactCallback for FlashCallback {
    fn call<'a>(
        &'a self,
        id: &'a str,
        artifact_name: &'a str,
        type_name: &'a str,
        meta_data: &'a str,
        filename: &'a str,
        size: usize,
        data: &'a [u8],
        index: usize,
        length: usize,
    ) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'a>> {
        Box::pin(async move {
            mender_client_download_artifact_flash_callback(
                id,
                artifact_name,
                type_name,
                meta_data,
                filename,
                size,
                data,
                index,
                length,
            )
            .await
        })
    }
}

pub async fn mender_client_init(
    spawner: &Spawner,
    config: &MenderClientConfig,
    callbacks: &MenderClientCallbacks,
    trng: &'static mut Trng<'static>,
    //stack: &'static Stack<WifiDevice<'static, WifiStaDevice>>
    stack: Stack<'static>,
) -> MenderResult<()> {
    // Store RNG
    let mut rng_lock = MENDER_CLIENT_RNG.lock().await;
    *rng_lock = Some(StaticTrng(trng));

    // Validate configuration
    if config.artifact_name.is_empty()
        || config.device_type.is_empty()
        || config.identity.is_empty()
    {
        log::error!("Invalid artifact name, can't be empty");
        return Err(MenderError::Other);
    }

    // Copy configuration
    let mut saved_config = config.clone();

    // Print out identity contents
    log::info!("Identity contents: {:?}", saved_config.identity);

    // Handle host configuration
    saved_config.host = if !config.host.is_empty() {
        config.host.clone()
    } else {
        CONFIG_MENDER_SERVER_HOST.to_string()
    };

    // Validate host configuration
    if saved_config.host.is_empty() {
        log_error!("Invalid server host configuration, can't be empty");
        return Err(MenderError::Other);
    }

    if saved_config.host.ends_with('/') {
        log_error!("Invalid server host configuration, trailing '/' is not allowed");
        return Err(MenderError::Other);
    }

    // Handle tenant token
    saved_config.tenant_token = match &config.tenant_token {
        Some(token) if !token.is_empty() => Some(token.to_string()),
        _ => {
            // If no token provided or empty, use default
            if !CONFIG_MENDER_SERVER_TENANT_TOKEN.is_empty() {
                Some(CONFIG_MENDER_SERVER_TENANT_TOKEN.to_string())
            } else {
                None
            }
        }
    };

    // If token is empty string, set to None
    if let Some(token) = &saved_config.tenant_token {
        if token.is_empty() {
            saved_config.tenant_token = None;
        }
    }

    // Set default poll intervals
    if config.authentication_poll_interval != 0 {
        saved_config.authentication_poll_interval = config.authentication_poll_interval;
    } else {
        saved_config.authentication_poll_interval = CONFIG_MENDER_AUTH_POLL_INTERVAL;
    }

    if config.update_poll_interval != 0 {
        saved_config.update_poll_interval = config.update_poll_interval;
    } else {
        saved_config.update_poll_interval = CONFIG_MENDER_UPDATE_POLL_INTERVAL;
    }

    let mender_api_config = MenderApiConfig {
        identity: saved_config.identity.clone(),
        artifact_name: saved_config.artifact_name.clone(),
        device_type: saved_config.device_type.clone(),
        host: saved_config.host.clone(),
        tenant_token: saved_config.tenant_token.as_ref().map(|s| s.to_string()),
    };

    // Initialize the scheduler
    mender_scheduler_init(*spawner).expect("Failed to init scheduler");

    if let Err(_) = mender_storage::mender_storage_init().await {
        log_error!("Unable to initialize storage");
        return Err(MenderError::Other);
    }

    // Initialize TLS
    if let Err(_) = mender_tls::mender_tls_init().await {
        log_error!("Unable to initialize TLS");
        return Err(MenderError::Other);
    }

    mender_api_init(&mender_api_config, stack)
        .await
        .expect("Failed to init mender api");

    // Use the static FLASH_CALLBACK instead of creating a new instance
    if let Err(_) = mender_client_register_artifact_type(
        "rootfs-image",
        &FLASH_CALLBACK,
        true,
        &saved_config.artifact_name,
    )
    .await
    {
        log_error!("Unable to register 'rootfs-image' artifact type");
        return Err(MenderError::Other);
    }

    let work = mender_scheduler_work_create(
        mender_client_work,
        saved_config.authentication_poll_interval,
        "mender_client_update",
    )
    .await
    .expect("Failed to create work");

    let mut client_work = MENDER_CLIENT_WORK.lock().await;
    *client_work = Some(work);

    let mut conf = MENDER_CLIENT_CONFIG.lock().await;
    *conf = Some(saved_config);

    let mut cb = MENDER_CLIENT_CALLBACKS.lock().await;
    *cb = Some(callbacks.clone());

    Ok(())
}

pub async fn mender_client_get_artifact_name() -> Option<String> {
    MENDER_CLIENT_CONFIG
        .lock()
        .await
        .as_ref()
        .map(|config| config.artifact_name.to_string())
}

pub async fn mender_client_get_device_type() -> Option<String> {
    MENDER_CLIENT_CONFIG
        .lock()
        .await
        .as_ref()
        .map(|config| config.device_type.to_string())
}

pub async fn mender_client_register_artifact_type(
    type_name: &str,
    callback: &'static dyn MenderArtifactCallback,
    needs_restart: bool,
    artifact_name: &str,
) -> MenderResult<()> {
    // Validate input
    if type_name.is_empty() {
        log_error!("Type name cannot be empty");
        return Err(MenderError::Failed);
    }

    // Create new artifact type handler
    let artifact_type = ArtifactTypeHandler {
        type_name: HString::<32>::try_from(type_name).map_err(|_| {
            log_error!("Type name too long");
            MenderError::Failed
        })?,
        callback,
        needs_restart,
        artifact_name: HString::<32>::try_from(artifact_name).map_err(|_| {
            log_error!("Artifact name too long");
            MenderError::Failed
        })?,
    };

    // Take mutex to protect access to the artifact types list
    let mut artifact_types = MENDER_CLIENT_ARTIFACT_TYPES.lock().await;

    // Initialize the vector if it doesn't exist
    if artifact_types.is_none() {
        *artifact_types = Some(HVec::new());
    }

    // Add the new artifact type to the list
    if let Some(types) = artifact_types.as_mut() {
        if types.push(artifact_type).is_err() {
            log_error!("Unable to add artifact type: list is full");
            return Err(MenderError::Failed);
        }
    }

    Ok(())
}

pub async fn mender_client_register_addon<C: 'static, CB: 'static>(
    addon: &'static MenderAddonInstance<C, CB>,
    config: Option<&'static C>,
    callbacks: Option<&'static CB>,
) -> MenderResult<()> {
    let mut addons = MENDER_CLIENT_ADDONS.lock().await;

    // Initialize the add-on
    (addon.init)(config, callbacks).await?;

    // Activate add-on if authentication is already done
    let state = MENDER_CLIENT_STATE.lock().await;
    if *state == MenderClientState::MenderClientStateAuthenticated {
        if let Err(e) = addon.activate().await {
            log_error!("Unable to activate add-on");
            // Cleanup on failure
            if let Err(e) = addon.exit().await {
                log_error!("Add-on exit failed: ", "error" => e);
            }
            return Err(e);
        }
    }

    // Add add-on to the list using the trait object
    addons.push(addon as &'static dyn MenderAddon);

    Ok(())
}

pub async fn mender_client_activate() -> MenderError {
    log_info!("mender_client_activate");
    let mut client_work = MENDER_CLIENT_WORK.lock().await;

    let work = match client_work.as_mut() {
        Some(w) => w,
        None => return MenderError::Other,
    };

    if mender_scheduler_work_activate(work).await.is_ok() {
        log_info!("mender_client_activate: update work activated");
        MenderError::Done
    } else {
        log::error!("Unable to activate update work");
        MenderError::Other
    }
}

async fn deactivate_addons() -> MenderResult<()> {
    let addons = MENDER_CLIENT_ADDONS.lock().await;

    // Deactivate each addon
    for addon in addons.iter() {
        if let Err(e) = addon.deactivate().await {
            log_error!("Failed to deactivate addon");
            return Err(e);
        }
    }

    Ok(())
}

pub async fn mender_client_deactivate() -> MenderError {
    // Deactivate add-ons
    if let Err(e) = deactivate_addons().await {
        log_error!("Failed to deactivate addons");
        return e;
    }

    let mut client_work = MENDER_CLIENT_WORK.lock().await;

    let work = match client_work.as_mut() {
        Some(w) => w,
        None => return MenderError::Other,
    };

    if mender_scheduler_work_deactivate(work).await.is_ok() {
        MenderError::Done
    } else {
        log::error!("Unable to deactivate update work");
        MenderError::Other
    }
}

pub async fn mender_client_network_connect() -> MenderResult<()> {
    log_info!("mender_client_network_connect");
    let mut count = MENDER_CLIENT_NETWORK_COUNT.lock().await;

    // Check if this is the first network user
    if *count == 0 {
        // Request network access if callback exists
        let callbacks = MENDER_CLIENT_CALLBACKS.lock().await;
        if let Some(cb) = callbacks.as_ref() {
            (cb.network_connect)()?;
        }
    }

    // Increment network management counter
    *count += 1;

    Ok(())
}

pub async fn mender_client_network_release() -> MenderResult<()> {
    let mut count = MENDER_CLIENT_NETWORK_COUNT.lock().await;

    // Decrement network management counter
    *count = count.saturating_sub(1);

    // Check if this was the last network user
    if *count == 0 {
        // Release network access if callback exists
        let callbacks = MENDER_CLIENT_CALLBACKS.lock().await;
        if let Some(cb) = callbacks.as_ref() {
            (cb.network_release)()?;
        }
    }

    Ok(())
}

async fn release_addons() -> MenderResult<()> {
    let mut addons = MENDER_CLIENT_ADDONS.lock().await;

    // Release each addon
    for addon in addons.iter() {
        if let Err(e) = addon.exit().await {
            log_error!("Failed to exit addon");
            return Err(e);
        }
    }

    // Clear the addons list
    addons.clear();

    Ok(())
}

pub async fn mender_client_exit() -> MenderError {
    // Release add-ons
    if let Err(e) = release_addons().await {
        log_error!("Failed to release addons");
        return e;
    }

    let mut client_work = MENDER_CLIENT_WORK.lock().await;

    if let Some(work) = client_work.take() {
        if mender_scheduler_work_delete(&work).await.is_ok() {
            log::info!("Update work deleted");
        } else {
            log::error!("Unable to delete update work");
        }
    }

    /* Release all modules */
    mender_api::mender_api_exit().await;
    if let Err(_) = mender_tls::mender_tls_exit().await {
        log_error!("Unable to exit TLS");
        return MenderError::Failed;
    }
    let _ = mender_storage::mender_storage_exit().await;
    if let Err(_) = mender_scheduler::mender_scheduler_work_delete_all().await {
        log_error!("Failed to delete all scheduler work");
        return MenderError::Failed;
    }

    MenderError::Done
}

// In your client code
async fn mender_client_work_function() -> MenderError {
    log_info!("mender_client_work_function");

    let mut state = MENDER_CLIENT_STATE.lock().await;
    if *state == MenderClientState::MenderClientStateInitialization {
        // Perform initialization of the client
        match mender_client_initialization_work_function().await {
            Ok(_) => {
                // Update client state
                *state = MenderClientState::MenderClientStateAuthentication;
            }
            Err(e) => return e,
        }
    }

    match mender_client_network_connect().await {
        Ok(_) => (),
        Err(e) => return e,
    }

    // Intentional pass-through
    if *state == MenderClientState::MenderClientStateAuthentication {
        // Perform authentication with the server
        if let Err(e) = mender_client_authentication_work_function().await {
            return e;
        }

        let period = {
            let config = MENDER_CLIENT_CONFIG.lock().await;
            config.as_ref().map(|c| c.update_poll_interval).unwrap_or(0)
        };

        let work_context = {
            let mut work = MENDER_CLIENT_WORK.lock().await;
            work.as_mut().cloned() // Clone the work context
        };

        if let Some(mut w) = work_context {
            log_info!("mender_client_work_function: setting work period", "period" => period);
            if let Err(_) = mender_scheduler::mender_scheduler_work_set_period(&mut w, period).await
            {
                log_error!("Unable to set work period");
                return MenderError::Other;
            }
        }

        log_info!("mender_client_work_function: setting work period done");
        // Update client state
        *state = MenderClientState::MenderClientStateAuthenticated;
    }

    /* Intentional pass-through */
    if *state == MenderClientState::MenderClientStateAuthenticated {
        // Perform updates
        mender_client_update_work_function().await
    } else {
        MenderError::Done
    }
}

fn mender_client_work() -> MenderFuture {
    Box::pin(async {
        match mender_client_work_function().await {
            MenderError::Done => Ok(()),
            _ => Err("Work failed"),
        }
    })
}

async fn mender_client_initialization_work_function() -> MenderResult<()> {
    log_info!("mender_client_initialization_work_function");
    // Retrieve or generate authentication keys
    let config = MENDER_CLIENT_CONFIG.lock().await;
    let recommissioning = config.as_ref().map(|c| c.recommissioning).unwrap_or(false);

    let mut lock = MENDER_CLIENT_RNG.lock().await;
    let rng = lock.as_mut().ok_or(MenderError::Failed)?;

    mender_tls::mender_tls_init_authentication_keys(&mut rng.get_trng(), recommissioning).await?;

    // Retrieve deployment data if it exists
    match mender_storage::mender_storage_get_deployment_data().await {
        Ok(deployment_data) => {
            // Parse deployment data using from_str
            match from_str::<DeploymentData>(&deployment_data) {
                Ok((json_data, _)) => {
                    let mut deployment = MENDER_CLIENT_DEPLOYMENT_DATA.lock().await;
                    *deployment = Some(json_data);
                    log::debug!("Successfully parsed deployment data");
                }
                Err(e) => {
                    log::error!("Failed to parse deployment data: {:?}", e);
                    mender_storage::mender_storage_delete_deployment_data().await?;

                    let callbacks = MENDER_CLIENT_CALLBACKS.lock().await;
                    if let Some(cb) = callbacks.as_ref() {
                        if let Err(e) = (cb.restart)() {
                            log::error!("Restart callback failed: {:?}", e);
                            return Err(e);
                        }
                    }
                    return Err(MenderError::Failed);
                }
            }
        }
        Err(MenderError::NotFound) => {
            log_info!("No deployment data found");
        }
        Err(e) => {
            log_error!("Failed to get deployment data:", "error" => e);
            mender_storage::mender_storage_delete_deployment_data().await?;

            let callbacks = MENDER_CLIENT_CALLBACKS.lock().await;
            if let Some(cb) = callbacks.as_ref() {
                if let Err(e) = (cb.restart)() {
                    log::error!("Restart callback failed: {:?}", e);
                    return Err(e);
                }
            }
            return Err(MenderError::Failed);
        }
    }

    Ok(())
}

pub struct MyDownLoad;

impl MenderCallback for MyDownLoad {
    fn call<'a>(
        &'a self,
        type_str: Option<&'a str>,
        meta: Option<&'a str>,
        file: Option<&'a str>,
        size: usize,
        data: &'a [u8],
        index: usize,
        length: usize,
    ) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'a>> {
        Box::pin(async move {
            mender_client_download_artifact_callback(
                type_str, meta, file, size, data, index, length,
            )
            .await
        })
    }
}

async fn mender_client_update_work_function() -> MenderError {
    // Check for deployment
    log_info!("mender_client_update_work_function");
    let deployment = match mender_api::mender_api_check_for_deployment().await {
        Ok((id, artifact_name, uri)) => {
            // Check if deployment is available
            if id.is_empty() || artifact_name.is_empty() || uri.is_empty() {
                log_info!("No deployment available");
                return MenderError::Done;
            }
            Some((id, artifact_name, uri))
        }
        Err(e) => {
            log_error!("Unable to check for deployment");
            return e;
        }
    };

    let (id, artifact_name, uri) = deployment.unwrap();

    // Reset flags
    let mut needs_set_pending_image = MENDER_CLIENT_DEPLOYMENT_NEEDS_SET_PENDING_IMAGE
        .lock()
        .await;
    let mut needs_restart = MENDER_CLIENT_DEPLOYMENT_NEEDS_RESTART.lock().await;
    *needs_set_pending_image = false;
    *needs_restart = false;

    // Create deployment data manually
    let deployment_data: heapless::String<256> = match serde_json_core::ser::to_string(&[
        ("id", id.as_str()),
        ("artifact_name", artifact_name.as_str()),
        ("types", "[]"),
    ]) {
        Ok(data) => data,
        Err(e) => {
            log_error!("Unable to serialize deployment data:", "error" => e);
            return MenderError::Failed;
        }
    };

    // Download deployment artifact
    log_info!("Downloading deployment artifact with id", "id" => id, "artifact name" => artifact_name, "uri" => uri);
    mender_client_publish_deployment_status(&id, DeploymentStatus::Downloading).await;

    let download_callback = MyDownLoad;

    match mender_api::mender_api_download_artifact(&uri, Some(&download_callback)).await {
        Ok(_) => (),
        Err(e) => {
            log_error!("Unable to download artifact");
            mender_client_publish_deployment_status(&id, DeploymentStatus::Failure).await;
            if *needs_set_pending_image {
                match mender_flash::mender_flash_abort_deployment().await {
                    Ok(_) => (),
                    Err(e) => return e,
                }
            }
            return e;
        }
    }

    // Set boot partition
    log_info!("Download done, installing artifact");
    mender_client_publish_deployment_status(&id, DeploymentStatus::Installing).await;
    if *needs_set_pending_image {
        if let Err(e) = mender_flash::mender_flash_set_pending_image().await {
            log_error!("Unable to set boot partition");
            mender_client_publish_deployment_status(&id, DeploymentStatus::Failure).await;
            return e;
        }
    }

    // Handle restart case
    if *needs_restart {
        // Save deployment data
        let deployment_str: heapless::String<256> =
            match serde_json_core::to_string(&deployment_data) {
                Ok(str) => str,
                Err(_) => return MenderError::Failed,
            };

        match mender_storage::mender_storage_set_deployment_data(&deployment_str).await {
            Ok(_) => (),
            Err(e) => {
                log_error!("Unable to save deployment data");
                mender_client_publish_deployment_status(&id, DeploymentStatus::Failure).await;
                return e;
            }
        }
        mender_client_publish_deployment_status(&id, DeploymentStatus::Rebooting).await;

        // Get callbacks and trigger restart
        let callbacks = MENDER_CLIENT_CALLBACKS.lock().await;
        if let Some(cb) = callbacks.as_ref() {
            match (cb.restart)() {
                Ok(_) => (),
                Err(e) => return e,
            }
        }
    } else {
        // Publish success if no restart needed
        mender_client_publish_deployment_status(&id, DeploymentStatus::Success).await;
    }

    MenderError::Done
}

async fn mender_client_publish_deployment_status(
    id: &str,
    status: DeploymentStatus,
) -> MenderError {
    log_info!("mender_client_publish_deployment_status", "id" => id, "status" => status);
    // Publish status to the mender server
    let ret = mender_api::mender_api_publish_deployment_status(id, status).await;

    // Invoke deployment status callback if defined
    let callbacks = MENDER_CLIENT_CALLBACKS.lock().await;
    if let Some(cb) = callbacks.as_ref() {
        let _ = (cb.deployment_status)(status, Some(status.as_str()));
    }

    match ret {
        Ok(_) => MenderError::Done,
        Err(e) => e,
    }
}

async fn mender_client_download_artifact_callback(
    artifact_type: Option<&str>,
    meta_data: Option<&str>,
    filename: Option<&str>,
    size: usize,
    data: &[u8],
    index: usize,
    length: usize,
) -> MenderResult<()> {
    // Get deployment data
    let mut deployment_data = MENDER_CLIENT_DEPLOYMENT_DATA.lock().await;
    let deployment = deployment_data.as_mut().ok_or(MenderError::Failed)?;

    // Get artifact types list
    let artifact_types = MENDER_CLIENT_ARTIFACT_TYPES.lock().await;

    // Check if we have any registered types
    if let Some(types_list) = artifact_types.as_ref() {
        // Look for matching type handler
        for artifact_handler in types_list.iter() {
            if let Some(artifact_type_str) = artifact_type {
                if artifact_handler.type_name == artifact_type_str {
                    // Get deployment ID and artifact name
                    let id = &deployment.id;

                    let artifact_name = &deployment.artifact_name;

                    log::info!(
                        "Processing artifact: type={}, id={}, artifact_name={}, index={}, length={}",
                        artifact_type_str, id, artifact_name, index, length
                    );

                    // Invoke callback for the artifact type
                    let meta_data_str = meta_data.unwrap_or("");
                    (artifact_handler.callback)
                        .call(
                            id,
                            artifact_name,
                            artifact_type_str,
                            meta_data_str,
                            filename.unwrap_or("default_filename"),
                            size,
                            data,
                            index,
                            length,
                        )
                        .await?;

                    // Handle first chunk special case
                    if index == 0 {
                        log_info!("Adding artifact type to the deployment data", "artifact_type" => artifact_type_str);
                        log_info!("Deployment data", "deployment_data.types" => deployment_data.as_ref().unwrap().types);

                        // Add artifact type to the deployment data if not already present
                        let type_str =
                            HString::<MAX_JSON_STRING_SIZE>::try_from(artifact_type_str).unwrap();
                        if deployment_data
                            .as_mut()
                            .unwrap()
                            .types
                            .push(type_str)
                            .is_err()
                        {
                            log::warn!(
                                "Unable to add artifact type '{}': types list is full",
                                artifact_type_str
                            );
                            return Err(MenderError::Failed);
                        }

                        // Set restart flag if needed
                        if artifact_handler.needs_restart {
                            let mut needs_restart =
                                MENDER_CLIENT_DEPLOYMENT_NEEDS_RESTART.lock().await;
                            *needs_restart = true;
                        }
                    }

                    return Ok(());
                }
            }
        }
    }

    // No matching handler found
    log::error!(
        "Unable to handle artifact type '{}'",
        artifact_type.unwrap_or("")
    );
    Err(MenderError::Failed)
}

async fn mender_client_authentication_work_function() -> MenderResult<()> {
    log_info!("mender_client_authentication_work_function");
    // Perform authentication with the mender server
    if let Err(e) = mender_api::mender_api_perform_authentication().await {
        // Invoke authentication error callback
        let callbacks = MENDER_CLIENT_CALLBACKS.lock().await;
        if let Some(cb) = callbacks.as_ref() {
            if let Err(_) = (cb.authentication_failure)() {
                // Check if deployment is pending
                let deployment = MENDER_CLIENT_DEPLOYMENT_DATA.lock().await;
                if deployment.is_some() {
                    log_error!("Authentication error callback failed, rebooting");
                    // Invoke restart callback
                    if let Err(e) = (cb.restart)() {
                        return Err(e);
                    }
                }
            }
        }
        return Err(e);
    }

    // Invoke authentication success callback
    let callbacks = MENDER_CLIENT_CALLBACKS.lock().await;
    if let Some(cb) = callbacks.as_ref() {
        if let Err(_) = (cb.authentication_success)() {
            // Check if deployment is pending
            let deployment = MENDER_CLIENT_DEPLOYMENT_DATA.lock().await;
            if deployment.is_some() {
                log_error!("Authentication success callback failed, rebooting");
                if let Err(e) = (cb.restart)() {
                    return Err(e);
                }
            }
        }
    }

    // Check if deployment is pending
    let mut deployment_data = MENDER_CLIENT_DEPLOYMENT_DATA.lock().await;
    if let Some(deployment) = deployment_data.as_ref() {
        // Get deployment ID and artifact name
        let id = &deployment.id;
        let artifact_name = &deployment.artifact_name;
        let types = &deployment.types;

        // Check if artifact running is the pending one
        let mut success = true;
        let artifact_types = MENDER_CLIENT_ARTIFACT_TYPES.lock().await;

        if let Some(type_list) = artifact_types.as_ref() {
            for deployment_type in types.iter() {
                for artifact_type in type_list.iter() {
                    if artifact_type.type_name == *deployment_type {
                        if artifact_type.artifact_name != *artifact_name {
                            success = false;
                        }
                    }
                }
            }
        }

        // Publish deployment status
        if success {
            mender_client_publish_deployment_status(id, DeploymentStatus::Success).await;
        } else {
            mender_client_publish_deployment_status(id, DeploymentStatus::Failure).await;
        }

        // Delete pending deployment
        mender_storage::mender_storage_delete_deployment_data().await?;
    }

    // Clear deployment data
    *deployment_data = None;

    // Activate add-ons after successful authentication
    if let Err(e) = activate_addons().await {
        log_error!("Failed to activate addons");
        return Err(e);
    }

    Ok(())
}

async fn activate_addons() -> MenderResult<()> {
    log_info!("activate_addons");
    let addons = MENDER_CLIENT_ADDONS.lock().await;

    // Activate each addon
    for addon in addons.iter() {
        if let Err(e) = addon.activate().await {
            log_error!("Failed to activate addon");
            return Err(e);
        }
    }

    Ok(())
}

async fn mender_client_download_artifact_flash_callback(
    _id: &str,
    _artifact_name: &str,
    _type_name: &str,
    _meta_data: &str,
    filename: &str,
    size: usize,
    data: &[u8],
    index: usize,
    length: usize,
) -> MenderResult<()> {
    // Only proceed if filename is not empty
    if !filename.is_empty() {
        // Open flash handle if this is the first chunk
        if index == 0 {
            match mender_flash::mender_flash_open(filename, size).await {
                Ok(_) => (),
                Err(e) => {
                    log_error!("Unable to open flash handle", "filename" => filename, "size" => size);
                    return Err(e);
                }
            }
        }

        // Write data to flash
        if let Err(e) = mender_flash::mender_flash_write(data, index, length).await {
            log_error!("Unable to write data to flash", "filename" => filename, "size" => size, "index" => index, "length" => length);
            return Err(e);
        }

        // Close flash handle if this is the last chunk
        if index + length >= size {
            if let Err(e) = mender_flash::mender_flash_close().await {
                log_error!("Unable to close flash handle", "filename" => filename, "size" => size);
                return Err(e);
            }
        }
    }

    // Set pending image flag
    let mut needs_set_pending_image = MENDER_CLIENT_DEPLOYMENT_NEEDS_SET_PENDING_IMAGE
        .lock()
        .await;
    *needs_set_pending_image = true;

    Ok(())
}
