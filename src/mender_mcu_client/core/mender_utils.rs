extern crate alloc;

#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::string::{String, ToString};
use core::fmt;
use core::fmt::Write;
use heapless::{FnvIndexMap, String as HeaplessString};
use heapless::{String as HString, Vec as HVec};
use serde::{Deserialize, Serialize};
use serde_json_core::ser;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MenderError {
    Done,
    Ok,
    Failed,
    NotFound,
    NotImplemented,
    Other,
}

pub type MenderResult<T> = core::result::Result<T, MenderError>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeploymentStatus {
    Downloading,
    Installing,
    Rebooting,
    Success,
    Failure,
    AlreadyInstalled,
}

impl DeploymentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeploymentStatus::Downloading => "downloading",
            DeploymentStatus::Installing => "installing",
            DeploymentStatus::Rebooting => "rebooting",
            DeploymentStatus::Success => "success",
            DeploymentStatus::Failure => "failure",
            DeploymentStatus::AlreadyInstalled => "already-installed",
        }
    }
}

impl fmt::Display for DeploymentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

const MAX_STRING_SIZE: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStoreItem {
    pub name: HString<MAX_STRING_SIZE>,
    pub value: HString<MAX_STRING_SIZE>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStore {
    pub items: HVec<KeyStoreItem, MAX_STRING_SIZE>,
}

impl KeyStore {
    pub fn new() -> Self {
        KeyStore { items: HVec::new() }
    }

    pub fn with_capacity(_capacity: usize) -> Self {
        KeyStore {
            items: HVec::<KeyStoreItem, MAX_STRING_SIZE>::new(),
        }
    }

    pub fn set_item(&mut self, name: &str, value: &str) -> MenderResult<()> {
        if let Some(item) = self.items.iter_mut().find(|item| item.name == name) {
            let mut hvalue = HString::<MAX_STRING_SIZE>::new();
            hvalue.push_str(value).map_err(|_| MenderError::Failed)?;
            item.value = hvalue;
        } else {
            let mut hname = HString::<MAX_STRING_SIZE>::new();
            let mut hvalue = HString::<MAX_STRING_SIZE>::new();

            hname.push_str(name).map_err(|_| MenderError::Failed)?;
            hvalue.push_str(value).map_err(|_| MenderError::Failed)?;

            self.items
                .push(KeyStoreItem {
                    name: hname,
                    value: hvalue,
                })
                .map_err(|_| MenderError::Failed)?;
        }
        Ok(())
    }

    pub fn get_item(&self, name: &str) -> Option<&str> {
        self.items
            .iter()
            .find(|item| item.name == name)
            .map(|item| item.value.as_str())
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn clear(&mut self) -> MenderResult<()> {
        self.items.clear();
        Ok(())
    }

    pub fn copy_from(&mut self, src: &KeyStore) -> MenderResult<()> {
        // Ensure there is enough capacity for both existing and new items
        if self.items.len() + src.len() > self.items.capacity() {
            log_error!("Not enough capacity to copy items");
            return Err(MenderError::Failed);
        }

        // Copy all items from source
        for item in &src.items {
            self.items
                .push(KeyStoreItem {
                    name: item.name.clone(),
                    value: item.value.clone(),
                })
                .map_err(|_| MenderError::Failed)?;
        }

        Ok(())
    }

    pub fn create_copy(src: &KeyStore) -> MenderResult<Self> {
        let mut new_store = KeyStore::with_capacity(src.len());
        new_store.copy_from(src)?;
        Ok(new_store)
    }

    /// Deserialize a KeyStore from a JSON object
    pub fn from_json(json: &FnvIndexMap<&str, &str, 16>) -> MenderResult<Self> {
        let mut keystore = KeyStore::with_capacity(json.len());

        for (key, value) in json.iter() {
            keystore.set_item(key, value)?;
        }

        Ok(keystore)
    }

    /// Updates an existing KeyStore with data from a JSON object
    pub fn update_from_json(&mut self, json: &FnvIndexMap<&str, &str, 16>) -> MenderResult<()> {
        for (key, value) in json.iter() {
            self.set_item(key, value)?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> MenderResult<String> {
        // Create a fixed-capacity map for JSON serialization
        let mut json_map: FnvIndexMap<&str, &str, 16> = FnvIndexMap::new();

        // Populate the map with items from the KeyStore
        for item in &self.items {
            let key = item.name.as_str();
            let value = item.value.as_str();

            // Insert into the map, checking for capacity issues
            json_map
                .insert(key, value)
                .map_err(|_| MenderError::Failed)?;
        }

        // Serialize the map into a heapless::String
        let mut json_string = HeaplessString::<256>::new();
        write!(
            json_string,
            "{}",
            ser::to_string::<_, 256>(&json_map).map_err(|_| MenderError::Failed)?
        )
        .map_err(|_| MenderError::Failed)?;

        // Convert heapless::String to alloc::String
        Ok(json_string.to_string())
    }
}

pub fn mender_utils_keystore_to_json(keystore: &KeyStore) -> MenderResult<String> {
    log_info!("mender_utils_keystore_to_json");
    // Create a fixed-capacity map for JSON serialization
    let mut json_map: FnvIndexMap<&str, &str, 16> = FnvIndexMap::new();

    // Populate the map with items from the KeyStore
    for item in &keystore.items {
        let key = item.name.as_str();
        let value = item.value.as_str();

        // Insert into the map, checking for capacity issues
        json_map
            .insert(key, value)
            .map_err(|_| MenderError::Failed)?;
    }

    // Serialize the map into a heapless::String
    let mut json_string = HeaplessString::<256>::new();
    write!(
        json_string,
        "{}",
        ser::to_string::<_, 256>(&json_map).map_err(|_| MenderError::Failed)?
    )
    .map_err(|_| MenderError::Failed)?;

    // Convert heapless::String to alloc::String
    Ok(json_string.to_string())
}

pub fn mender_utils_http_status_to_string(status: i32) -> Option<&'static str> {
    match status {
        100 => Some("Continue"),
        101 => Some("Switching Protocols"),
        103 => Some("Early Hints"),
        200 => Some("OK"),
        201 => Some("Created"),
        202 => Some("Accepted"),
        203 => Some("Non-Authoritative Information"),
        204 => Some("No Content"),
        205 => Some("Reset Content"),
        206 => Some("Partial Content"),
        300 => Some("Multiple Choices"),
        301 => Some("Moved Permanently"),
        302 => Some("Found"),
        303 => Some("See Other"),
        304 => Some("Not Modified"),
        307 => Some("Temporary Redirect"),
        308 => Some("Permanent Redirect"),
        400 => Some("Bad Request"),
        401 => Some("Unauthorized"),
        402 => Some("Payment Required"),
        403 => Some("Forbidden"),
        404 => Some("Not Found"),
        405 => Some("Method Not Allowed"),
        406 => Some("Not Acceptable"),
        407 => Some("Proxy Authentication Required"),
        408 => Some("Request Timeout"),
        409 => Some("Conflict"),
        410 => Some("Gone"),
        411 => Some("Length Required"),
        412 => Some("Precondition Failed"),
        413 => Some("Payload Too Large"),
        414 => Some("URI Too Long"),
        415 => Some("Unsupported Media Type"),
        416 => Some("Range Not Satisfiable"),
        417 => Some("Expectation Failed"),
        418 => Some("I'm a teapot"),
        422 => Some("Unprocessable Entity"),
        425 => Some("Too Early"),
        426 => Some("Upgrade Required"),
        428 => Some("Precondition Required"),
        429 => Some("Too Many Requests"),
        431 => Some("Request Header Fields Too Large"),
        451 => Some("Unavailable For Legal Reasons"),
        500 => Some("Internal Server Error"),
        501 => Some("Not Implemented"),
        502 => Some("Bad Gateway"),
        503 => Some("Service Unavailable"),
        504 => Some("Gateway Timeout"),
        505 => Some("HTTP Version Not Supported"),
        506 => Some("Variant Also Negotiates"),
        507 => Some("Insufficient Storage"),
        508 => Some("Loop Detected"),
        510 => Some("Not Extended"),
        511 => Some("Network Authentication Required"),
        _ => None,
    }
}

// pub fn mender_utils_str_begins_with(s1: &str, s2: &str) -> bool {
//     s1.starts_with(s2)
// }

// pub fn mender_utils_str_ends_with(s1: &str, s2: &str) -> bool {
//     s1.ends_with(s2)
// }

// pub fn mender_utils_str_last_occurrence(haystack: &str, needle: &str) -> Option<usize> {
//     haystack.rfind(needle)
// }

// pub fn mender_utils_keystore_copy_from(dest: &mut KeyStore, src: &KeyStore) -> MenderResult<()> {
//     // Ensure there is enough capacity for both existing and new items
//     if dest.items.len() + src.len() > dest.items.capacity() {
//         log_error!("Not enough capacity to copy items");
//         return Err(MenderError::Failed);
//     }

//     // Copy all items from source
//     for item in &src.items {
//         dest.items.push(KeyStoreItem {
//             name: item.name.clone(),
//             value: item.value.clone(),
//         }).map_err(|_| MenderError::Failed)?;
//     }

//     Ok(())
// }
