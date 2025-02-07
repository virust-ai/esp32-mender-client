use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

use crate::mender_mcu_client::core::mender_utils::MenderResult;

// Create a struct to hold the parameters
pub struct MenderCallbackInfo<'a> {
    pub type_str: Option<&'a str>,
    pub meta: Option<&'a str>,
    pub file: Option<&'a str>,
    pub size: usize,
    pub data: &'a [u8],
    pub offset: usize,
    pub total: usize,
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
        size: usize,
        data: &'a [u8],
        index: usize,
        length: usize,
        chksum: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'a>>;
}
