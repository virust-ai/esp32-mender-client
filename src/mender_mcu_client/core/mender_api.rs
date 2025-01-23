extern crate alloc;

use crate::alloc::string::ToString;
use crate::custom::mender_common::MenderCallback;
use crate::mender_mcu_client::core::mender_artifact;
use crate::mender_mcu_client::core::mender_artifact::MenderArtifactContext;
use crate::mender_mcu_client::core::mender_utils;
use crate::mender_mcu_client::core::mender_utils::{
    DeploymentStatus, KeyStore, MenderResult, MenderStatus,
};
use crate::mender_mcu_client::platform::net::mender_http::HttpCallback;
use crate::mender_mcu_client::platform::net::mender_http::{
    self, HttpClientEvent, MenderHttpResponseData,
};
use crate::mender_mcu_client::platform::net::mender_http::{
    mender_http_exit, mender_http_init, HttpMethod, MenderHttpConfig,
};
use crate::mender_mcu_client::platform::tls::mender_tls;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use core::future::Future;
use core::pin::Pin;
use embassy_net::Stack;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use heapless::String as HString;
use serde::{Deserialize, Serialize};

#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};

// Authentication endpoints
pub const MENDER_API_PATH_POST_AUTHENTICATION_REQUESTS: &str =
    "/api/devices/v1/authentication/auth_requests";

// Deployment endpoints
pub const MENDER_API_PATH_GET_NEXT_DEPLOYMENT: &str =
    "/api/devices/v1/deployments/device/deployments/next";
pub const MENDER_API_PATH_PUT_DEPLOYMENT_STATUS: &str =
    "/api/devices/v1/deployments/device/deployments/{}/status";

// Helper function if you need formatted deployment status path
pub fn get_deployment_status_path(deployment_id: &str) -> String {
    MENDER_API_PATH_PUT_DEPLOYMENT_STATUS.replace("{}", deployment_id)
}

#[derive(Serialize, Deserialize)]
struct Payload<'a> {
    id_data: &'a str, // Changed to &str instead of String
    pubkey: &'a str,
}

#[derive(Clone)]
pub struct MenderApiConfig {
    pub identity: KeyStore,
    pub artifact_name: String,
    pub device_type: String,
    pub host: String,
    pub tenant_token: Option<String>,
}

// Global static configuration
static MENDER_API_CONFIG: Mutex<CriticalSectionRawMutex, Option<MenderApiConfig>> =
    Mutex::new(None);
static MENDER_API_JWT: Mutex<CriticalSectionRawMutex, Option<String>> = Mutex::new(None);
static MENDER_ARTIFACT_CTX: Mutex<CriticalSectionRawMutex, Option<MenderArtifactContext>> =
    Mutex::new(None);

//const MAX_STRING_SIZE: usize = TLS_PUBLIC_KEY_LENGTH * 2; // Adjust as needed

pub async fn mender_api_init(
    api_config: &MenderApiConfig,
    //stack: &'static Stack<WifiDevice<'static, WifiStaDevice>>
    stack: Stack<'static>,
) -> MenderResult<()> {
    // Validate required fields
    if api_config.artifact_name.is_empty()
        || api_config.device_type.is_empty()
        || api_config.host.is_empty()
    {
        return Err(MenderStatus::Other);
    }

    // Initialize HTTP client first
    let http_config = MenderHttpConfig {
        host: api_config.host.clone(),
    };
    mender_http_init(&http_config, stack)
        .await
        .expect("Failed to initialize HTTP client");

    // Lock the mutex and update the configuration
    {
        let mut conf = MENDER_API_CONFIG.lock().await;
        *conf = Some(api_config.clone());
    } // Mutex lock is released here

    Ok((MenderStatus::Ok, ()))
}

// Helper function to get config reference
pub async fn get_config() -> MenderResult<MenderApiConfig> {
    let conf = MENDER_API_CONFIG.lock().await;
    conf.as_ref()
        .ok_or(MenderStatus::Other)
        .cloned()
        .map(|config| (MenderStatus::Ok, config))
}

#[derive(Debug, serde::Deserialize)]
struct JsonResponse<'a> {
    error: Option<&'a str>,
}

fn mender_api_print_response_error(response: Option<&str>, status: i32) {
    // Get status description
    if let Some(desc) = mender_utils::mender_utils_http_status_to_string(status) {
        // Parse response if available
        if let Some(response_str) = response {
            match serde_json_core::de::from_str::<JsonResponse>(response_str) {
                Ok((parsed, _)) => {
                    if let Some(error) = parsed.error {
                        log::error!("[{}] {}: {}", status, desc, error);
                    } else {
                        log::error!("[{}] {}: unknown error", status, desc);
                    }
                }
                Err(_) => {
                    log::error!("[{}] {}: unable to parse error response", status, desc);
                }
            }
        } else {
            log::error!("[{}] {}: no response body", status, desc);
        }
    } else {
        log::error!("Unknown error occurred, status={}", status);
    }
}

#[allow(dead_code)]
pub async fn mender_api_exit() {
    let mut conf = MENDER_API_CONFIG.lock().await;
    *conf = None;

    let mut jwt = MENDER_API_JWT.lock().await;
    *jwt = None;

    mender_http_exit().await;
}

pub struct MyTextCallback;

impl HttpCallback for MyTextCallback {
    fn call<'a>(
        &'a self,
        event: HttpClientEvent,
        data: Option<&'a [u8]>,
        response_data: Option<&'a mut MenderHttpResponseData>,
        params: Option<&'a (dyn MenderCallback + Send + Sync)>,
    ) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'a>> {
        Box::pin(async move {
            // Call your async function here
            mender_api_http_text_callback(event, data, response_data, params)
        })
    }
}

#[derive(serde::Deserialize)]
struct Identity<'a> {
    mac: &'a str,
}

pub async fn mender_api_perform_authentication() -> MenderResult<()> {
    log_info!("mender_api_perform_authentication");
    // Get public key in PEM format
    let (_, public_key_pem) = mender_tls::mender_tls_get_public_key_pem()
        .await
        .map_err(|_| {
            log_error!("Unable to get public key");
            MenderStatus::Failed
        })?;

    // Format identity
    let config = MENDER_API_CONFIG.lock().await;
    let config = config.as_ref().ok_or(MenderStatus::Failed)?;

    let (_, json_identity) = mender_utils::mender_utils_keystore_to_json(&config.identity)
        .map_err(|_| {
            log_error!("Unable to format identity");
            MenderStatus::Failed
        })?;

    // log_info!("json_identity", "json_identity" => json_identity);
    // log_info!("public_key_pem", "public_key_pem" => public_key_pem);

    let (identity, _): (Identity, _) =
        serde_json_core::from_str(json_identity.as_str()).map_err(|_| {
            log_error!("Failed to parse identity json");
            MenderStatus::Failed
        })?;

    let escaped_public_key = public_key_pem
        .trim_end() // Remove trailing whitespace/newlines first
        .replace('\n', "\\n");

    let payload_str = if let Some(tenant_token) = &config.tenant_token {
        format!(
            r#"{{"id_data": "{{\"mac\":\"{}\"}}", "pubkey": "{}", "tenant_token": "{}"}}"#,
            identity.mac, escaped_public_key, tenant_token
        )
    } else {
        format!(
            r#"{{"id_data": "{{\"mac\":\"{}\"}}", "pubkey": "{}"}}"#,
            identity.mac, escaped_public_key
        )
    };

    log_info!("Payload String", "payload_str" => payload_str);
    log_info!("Payload String length", "payload_str.len()" => payload_str.len());

    // Sign payload
    let (_, signature) = mender_tls::mender_tls_sign_payload(&payload_str)
        .await
        .map_err(|_| {
            log_error!("Unable to sign payload");
            MenderStatus::Failed
        })?;

    //log_info!("signature", "signature" => signature);

    let my_text_callback = MyTextCallback;
    let mut response_data = MenderHttpResponseData::default();
    let mut status = 0;
    // Perform HTTP request
    mender_http::mender_http_perform(
        None,
        MENDER_API_PATH_POST_AUTHENTICATION_REQUESTS,
        HttpMethod::Post,
        Some(&payload_str),
        Some(&signature),
        &my_text_callback,
        &mut response_data,
        &mut status,
        None,
    )
    .await
    .map_err(|_| {
        log_error!("Unable to perform HTTP request");
        MenderStatus::Failed
    })?;

    // Handle response
    if status == 200 {
        if response_data.text.as_ref().map_or(true, |t| t.is_empty()) {
            log_error!("Response is empty");
            return Err(MenderStatus::Failed);
        }

        let mut jwt = MENDER_API_JWT.lock().await;
        log_info!("response_data.text", "response_data.text" => response_data.text);
        *jwt = response_data.text;
        Ok((MenderStatus::Ok, ()))
    } else {
        log::error!(
            "Authentication failed with status {}: {}",
            status,
            response_data.text.unwrap_or_default()
        );
        Err(MenderStatus::Failed)
    }
}

pub fn mender_api_http_text_callback(
    event: HttpClientEvent,
    data: Option<&[u8]>,
    response_data: Option<&mut MenderHttpResponseData>,
    _params: Option<&(dyn MenderCallback + Send + Sync)>,
) -> MenderResult<()> {
    log_info!("mender_api_http_text_callback", "event" => event);
    let response_data = response_data.ok_or(MenderStatus::Failed)?;

    match event {
        HttpClientEvent::Connected => Ok((MenderStatus::Ok, ())),

        HttpClientEvent::DataReceived => {
            let data = data.ok_or_else(|| {
                log_error!("Invalid data received");
                MenderStatus::Failed
            })?;

            if data.is_empty() {
                log_info!("data is empty");
                return Ok((MenderStatus::Ok, ()));
            }

            // Convert data to string and append to response text
            if let Ok(text) = core::str::from_utf8(data) {
                log_info!("received text", "text" => text, "length" => text.len());
                match &mut response_data.text {
                    Some(existing) => existing.push_str(text),
                    None => response_data.text = Some(text.to_string()),
                }
                Ok((MenderStatus::Ok, ()))
            } else {
                log_error!("Invalid UTF-8 data received");
                Err(MenderStatus::Failed)
            }
        }

        HttpClientEvent::Disconnected => Ok((MenderStatus::Ok, ())),

        HttpClientEvent::Error => {
            log_error!("An error occurred");
            Err(MenderStatus::Failed)
        }
    }
}

pub async fn mender_api_get_authentication_token() -> MenderResult<String> {
    let jwt = MENDER_API_JWT.lock().await;
    jwt.as_ref()
        .ok_or(MenderStatus::Failed)
        .cloned()
        .map(|token| (MenderStatus::Ok, token))
}

pub async fn mender_api_check_for_deployment() -> MenderResult<(String, String, String)> {
    log_info!("mender_api_check_for_deployment");
    // Get current configuration
    let (_, config) = get_config().await?;
    let (_, jwt) = mender_api_get_authentication_token().await?;

    // Construct the query path with parameters
    let mut path = HString::<256>::new();
    path.push_str(MENDER_API_PATH_GET_NEXT_DEPLOYMENT)
        .map_err(|_| {
            log_error!("Failed to construct path");
            MenderStatus::Failed
        })?;
    path.push_str("?artifact_name=")
        .map_err(|_| MenderStatus::Failed)?;
    path.push_str(&config.artifact_name)
        .map_err(|_| MenderStatus::Failed)?;
    path.push_str("&device_type=")
        .map_err(|_| MenderStatus::Failed)?;
    path.push_str(&config.device_type)
        .map_err(|_| MenderStatus::Failed)?;

    // Prepare response data structure
    let my_text_callback = MyTextCallback;
    let mut response_data = MenderHttpResponseData::default();
    let mut status = 0;

    // Perform HTTP request
    mender_http::mender_http_perform(
        Some(&jwt),
        &path,
        HttpMethod::Get,
        None,
        None,
        &my_text_callback,
        &mut response_data,
        &mut status,
        None,
    )
    .await
    .map_err(|_| {
        log_error!("Unable to perform HTTP request");
        MenderStatus::Failed
    })?;

    match status {
        200 => {
            // Get response text
            let response_text = response_data.text.ok_or_else(|| {
                log_error!("No response data");
                MenderStatus::Failed
            })?;
            log_info!("response_text", "response_text" => response_text);

            // Parse JSON response using serde_json_core
            #[derive(serde::Deserialize)]
            struct JsonSource<'a> {
                uri: Option<&'a str>,
            }

            #[derive(serde::Deserialize)]
            struct JsonArtifact<'a> {
                artifact_name: Option<&'a str>,
                source: Option<JsonSource<'a>>,
            }

            #[derive(serde::Deserialize)]
            struct JsonDeployment<'a> {
                id: Option<&'a str>,
                artifact: Option<JsonArtifact<'a>>,
            }

            let (parsed, _): (JsonDeployment, _) = serde_json_core::de::from_str(&response_text)
                .map_err(|_| {
                    log_error!("Invalid JSON response");
                    MenderStatus::Failed
                })?;

            // Extract required fields
            let id = parsed.id.ok_or_else(|| {
                log_error!("Missing deployment ID");
                MenderStatus::Failed
            })?;

            let artifact = parsed.artifact.ok_or_else(|| {
                log_error!("Missing artifact data");
                MenderStatus::Failed
            })?;

            let artifact_name = artifact.artifact_name.ok_or_else(|| {
                log_error!("Missing artifact name");
                MenderStatus::Failed
            })?;

            let uri = artifact.source.and_then(|s| s.uri).ok_or_else(|| {
                log_error!("Missing artifact URI");
                MenderStatus::Failed
            })?;

            Ok((
                MenderStatus::Ok,
                (id.to_string(), artifact_name.to_string(), uri.to_string()),
            ))
        }
        204 => {
            log_info!("No deployment available");
            // No deployment available
            Ok((
                MenderStatus::Ok,
                (String::new(), String::new(), String::new()),
            ))
        }
        _ => {
            mender_api_print_response_error(response_data.text.as_deref(), status);
            Err(MenderStatus::Failed)
        }
    }
}

pub async fn mender_api_publish_deployment_status(
    id: &str,
    deployment_status: DeploymentStatus,
) -> MenderResult<()> {
    log_info!("mender_api_publish_deployment_status", "id" => id, "deployment_status" => deployment_status);
    // Get JWT token
    let (_, jwt) = mender_api_get_authentication_token().await?;

    // Convert deployment status to string
    let status_str = deployment_status.as_str();

    // Create payload using heapless types
    let mut payload = heapless::FnvIndexMap::<HString<32>, HString<32>, 2>::new();

    let mut status_key: HString<32> = HString::new();
    status_key.push_str("status").map_err(|_| {
        log_error!("Failed to create status key");
        MenderStatus::Failed
    })?;

    let mut status_value: HString<32> = HString::new();
    status_value.push_str(status_str).map_err(|_| {
        log_error!("Failed to create status value");
        MenderStatus::Failed
    })?;

    payload.insert(status_key, status_value).map_err(|_| {
        log_error!("Failed to insert status into payload");
        MenderStatus::Failed
    })?;

    // Serialize payload to JSON string
    let payload_str: HString<128> = serde_json_core::ser::to_string(&payload).map_err(|_| {
        log_error!("Failed to serialize payload");
        MenderStatus::Failed
    })?;

    // Compute path using the helper function
    let path = get_deployment_status_path(id);

    // Prepare response data structure
    let my_text_callback = MyTextCallback;
    let mut response_data = MenderHttpResponseData::default();
    let mut status = 0;

    // Perform HTTP request
    mender_http::mender_http_perform(
        Some(&jwt),
        &path,
        HttpMethod::Put,
        Some(&payload_str),
        None,
        &my_text_callback,
        &mut response_data,
        &mut status,
        None,
    )
    .await
    .map_err(|_| {
        log_error!("Unable to perform HTTP request");
        MenderStatus::Failed
    })?;

    // Handle response
    match status {
        204 => Ok((MenderStatus::Ok, ())), // Success, no content
        _ => {
            mender_api_print_response_error(response_data.text.as_deref(), status);
            Err(MenderStatus::Failed)
        }
    }
}

pub struct MyCallback;

impl HttpCallback for MyCallback {
    fn call<'a>(
        &'a self,
        event: HttpClientEvent,
        data: Option<&'a [u8]>,
        response_data: Option<&'a mut MenderHttpResponseData>,
        params: Option<&'a (dyn MenderCallback + Send + Sync)>,
    ) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'a>> {
        Box::pin(async move {
            // Call your async function here
            mender_api_http_artifact_callback(event, data, response_data, params).await
        })
    }
}

pub async fn mender_api_download_artifact(
    uri: &str,
    callback: Option<&(dyn MenderCallback + Send + Sync)>,
) -> MenderResult<()> {
    log_info!("mender_api_download_artifact");
    // Prepare response data structure
    let mut status = 0;
    let mut response_data = MenderHttpResponseData::default();

    let my_callback = MyCallback;

    // Perform HTTP request with artifact callback
    mender_http::mender_http_perform(
        None,
        uri,
        HttpMethod::Get,
        None,
        None,
        &my_callback,
        &mut response_data,
        &mut status,
        callback,
    )
    .await
    .map_err(|_| {
        log_error!("Unable to perform HTTP request");
        MenderStatus::Failed
    })?;

    // Handle response based on status
    match status {
        200 => Ok((MenderStatus::Ok, ())),
        _ => {
            mender_api_print_response_error(None, status);
            Err(MenderStatus::Failed)
        }
    }
}

// You'll also need this helper callback function
pub async fn mender_api_http_artifact_callback(
    event: HttpClientEvent,
    data: Option<&[u8]>,
    _response_data: Option<&mut MenderHttpResponseData>,
    params: Option<&(dyn MenderCallback + Send + Sync)>,
) -> MenderResult<()> {
    log_info!("mender_api_http_artifact_callback", "event" => event);
    match event {
        HttpClientEvent::Connected => {
            // Create new artifact context
            let mut ctx_lock = MENDER_ARTIFACT_CTX.lock().await;
            if ctx_lock.is_some() {
                return Ok((MenderStatus::Ok, ()));
            }

            // Initialize new context
            *ctx_lock = Some(MenderArtifactContext::new());
            Ok((MenderStatus::Ok, ()))
        }

        HttpClientEvent::DataReceived => {
            // Check input data
            let (data, data_length) = match data {
                Some(d) => (Some(d), d.len()),
                None => {
                    log_error!("Invalid data received");
                    return Err(MenderStatus::Failed);
                }
            };
            log_info!("data length", "data_length" => data_length);
            log_info!("");

            // Get artifact context and process data
            let mut ctx_lock = MENDER_ARTIFACT_CTX.lock().await;
            let ctx = match ctx_lock.as_mut() {
                Some(ctx) => ctx,
                None => {
                    log_error!("Invalid artifact context");
                    return Err(MenderStatus::Failed);
                }
            };

            // Process the data
            match params {
                Some(callback) => {
                    mender_artifact::mender_artifact_process_data(
                        ctx,
                        data,
                        data_length,
                        Some(callback),
                    )
                    .await
                }
                None => {
                    log_error!("Invalid callback");
                    Err(MenderStatus::Failed)
                }
            }
        }

        HttpClientEvent::Disconnected => {
            // Release artifact context
            let mut ctx_lock = MENDER_ARTIFACT_CTX.lock().await;
            *ctx_lock = None;
            Ok((MenderStatus::Ok, ()))
        }

        HttpClientEvent::Error => {
            log_error!("An error occurred");
            // Release artifact context
            let mut ctx_lock = MENDER_ARTIFACT_CTX.lock().await;
            *ctx_lock = None;
            Err(MenderStatus::Failed)
        }
    }
}
