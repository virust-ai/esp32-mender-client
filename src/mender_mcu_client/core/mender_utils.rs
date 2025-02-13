extern crate alloc;

#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MenderStatus {
    Done,
    Ok,
    Failed,
    NotFound,
    #[allow(dead_code)]
    NotImplemented,
    Other,
    Network,
}

pub type MenderResult<T> = core::result::Result<(MenderStatus, T), MenderStatus>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeploymentStatus {
    Downloading,
    Installing,
    Rebooting,
    Success,
    Failure,
    #[allow(dead_code)]
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

#[derive(Debug, Clone)]
pub struct KeyStoreItem {
    pub name: String,
    pub value: String,
}

// Add serialization implementation manually
impl Serialize for KeyStoreItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("KeyStoreItem", 2)?;
        state.serialize_field("name", &self.name.as_str())?;
        state.serialize_field("value", &self.value.as_str())?;
        state.end()
    }
}

// Add deserialization implementation manually
impl<'de> Deserialize<'de> for KeyStoreItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper<'a> {
            name: &'a str,
            value: &'a str,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(KeyStoreItem {
            name: helper.name.to_string(),
            value: helper.value.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct KeyStore {
    pub items: Vec<KeyStoreItem>,
}

impl Serialize for KeyStore {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.items.len()))?;
        for item in &self.items {
            seq.serialize_element(item)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for KeyStore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KeyStoreVisitor;

        impl<'de> serde::de::Visitor<'de> for KeyStoreVisitor {
            type Value = KeyStore;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a sequence of KeyStoreItems")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(KeyStore { items })
            }
        }

        deserializer.deserialize_seq(KeyStoreVisitor)
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore {
    pub fn new() -> Self {
        KeyStore { items: Vec::new() }
    }

    pub fn set_item(&mut self, name: &str, value: &str) -> MenderResult<()> {
        if let Some(item) = self.items.iter_mut().find(|item| item.name == name) {
            item.value = value.to_string();
        } else {
            self.items.push(KeyStoreItem {
                name: name.to_string(),
                value: value.to_string(),
            });
        }
        Ok((MenderStatus::Ok, ()))
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

pub fn mender_utils_keystore_to_json(keystore: &KeyStore) -> MenderResult<String> {
    log_debug!("mender_utils_keystore_to_json");

    // For a single key-value pair, format directly
    if keystore.items.len() == 1 {
        let item = &keystore.items[0];
        // Format with proper JSON syntax (using colon between key and value)
        let json = format!(r#"{{"{}":"{}"}}"#, item.name, item.value);
        return Ok((MenderStatus::Ok, json));
    }

    // For multiple items (though not expected in this case)
    let mut json = String::new();
    json.push('{');

    for (i, item) in keystore.items.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        // Format each key-value pair with proper JSON syntax
        json.push_str(&format!(r#""{}":"{}""#, item.name, item.value));
    }

    json.push('}');

    Ok((MenderStatus::Ok, json))
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

/// Find the last occurrence of a substring in a string
///
/// This is equivalent to the C function mender_utils_strrstr
pub fn mender_utils_strrstr<'a>(haystack: &'a str, needle: &str) -> Option<&'a str> {
    // Check if needle is empty
    if needle.is_empty() {
        return Some(&haystack[haystack.len()..]);
    }

    // Find last occurrence using forward search
    let mut last_pos = None;
    let mut current_pos = 0;

    while let Some(pos) = haystack[current_pos..].find(needle) {
        current_pos += pos;
        last_pos = Some(current_pos);
        current_pos += 1;
        if current_pos >= haystack.len() {
            break;
        }
    }

    // Return slice from the last found position if any
    last_pos.map(|pos| &haystack[pos..])
}
