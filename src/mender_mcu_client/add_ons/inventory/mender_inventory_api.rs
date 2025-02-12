extern crate alloc;

use crate::mender_mcu_client::core::mender_api::{
    mender_api_get_authentication_token, MyTextCallback,
};
use crate::mender_mcu_client::core::mender_utils::{KeyStore, MenderResult, MenderStatus};
use crate::mender_mcu_client::platform::net::mender_http::{
    self, HttpMethod, HttpRequestParams, MenderHttpResponseData,
};
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::format;
use alloc::string::String;

const MENDER_API_PATH_PUT_DEVICE_ATTRIBUTES: &str = "/api/devices/v1/inventory/device/attributes";

pub async fn mender_inventory_api_publish_inventory_data(
    artifact_name: Option<&str>,
    device_type: Option<&str>,
    inventory: Option<&[KeyStore]>,
) -> MenderResult<()> {
    log_info!("mender_inventory_api_publish_inventory_data");
    let mut object = String::new();

    if let Some(artifact_name) = artifact_name {
        object.push_str(&format!(
            r#"{{"name": "artifact_name", "value": "{}"}}"#,
            artifact_name
        ));
        object.push_str(&format!(
            r#",{{"name": "rootfs-image.version", "value": "{}"}}"#,
            artifact_name
        ));
    }

    if let Some(device_type) = device_type {
        if !object.is_empty() {
            object.push(',');
        }
        object.push_str(&format!(
            r#"{{"name": "device_type", "value": "{}"}}"#,
            device_type
        ));
    }

    if let Some(inventory) = inventory {
        for item in inventory {
            for key_store_item in &item.items {
                if !object.is_empty() {
                    object.push(',');
                }
                object.push_str(&format!(
                    r#"{{"name": "{}", "value": "{}"}}"#,
                    key_store_item.name, key_store_item.value
                ));
            }
        }
    }

    let payload = format!("[{}]", object);
    log_debug!("payload: {}", payload);

    let (_, jwt) = mender_api_get_authentication_token().await?;
    let my_text_callback = MyTextCallback;
    let mut response_data = MenderHttpResponseData::default();
    let mut status = 0;

    let ret = mender_http::mender_http_perform(HttpRequestParams {
        jwt: Some(&jwt),
        path: MENDER_API_PATH_PUT_DEVICE_ATTRIBUTES,
        method: HttpMethod::Put,
        payload: Some(&payload),
        signature: None,
        callback: &my_text_callback,
        response_data: &mut response_data,
        status: &mut status,
        params: None,
    })
    .await;

    if ret.is_err() || status != 200 {
        log_error!("Unable to perform HTTP request");
        return Err(MenderStatus::Failed);
    }

    Ok((MenderStatus::Ok, ()))
}
