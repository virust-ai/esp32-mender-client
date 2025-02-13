use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

use crate::mender_mcu_client::core::mender_utils::MenderResult;

// Create a struct to hold the parameters
pub struct MenderCallbackInfo<'a> {
    pub type_str: Option<&'a str>,
    pub meta: Option<&'a str>,
    pub file: Option<&'a str>,
    pub size: u32,
    pub data: &'a [u8],
    pub offset: u32,
    pub total: u32,
    pub chksum: &'a [u8],
}

// Define a trait for the callback to make it more flexible
pub trait MenderCallback {
    fn call<'a>(
        &'a self,
        mender_callback_info: MenderCallbackInfo<'a>,
    ) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'a>>;
}

// Define a new trait for the artifact type callback
pub trait MenderArtifactCallback: Sync {
    fn call<'a>(
        &'a self,
        // id: &'a str,
        // artifact_name: &'a str,
        // type_name: &'a str,
        // meta_data: &'a str,
        filename: &'a str,
        size: u32,
        data: &'a [u8],
        index: u32,
        length: u32,
        chksum: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'a>>;
}

// Custom serializer modules
pub mod serde_bytes_str {
    use crate::alloc::string::ToString;
    use alloc::string::String;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(string: &str, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        Ok(s.to_string())
    }
}

pub mod serde_bytes_str_vec {
    use crate::alloc::string::ToString;
    use alloc::string::String;
    use alloc::vec::Vec;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(vec: &Vec<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(vec.len()))?;
        for string in vec {
            seq.serialize_element(string.as_str())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVecVisitor;

        impl<'de> serde::de::Visitor<'de> for StringVecVisitor {
            type Value = Vec<String>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a sequence of strings")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(value) = seq.next_element::<&str>()? {
                    vec.push(value.to_string());
                }
                Ok(vec)
            }
        }

        deserializer.deserialize_seq(StringVecVisitor)
    }
}
