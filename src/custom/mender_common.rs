use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

use crate::mender_mcu_client::core::mender_utils::MenderResult;

// #[derive(Debug, serde::Deserialize)]
// pub struct JsonResponse<'a> {
//     pub text: &'a str,
// }

// impl<'a> JsonResponse<'a> {
//     pub fn as_str(&self) -> &str {
//         self.text
//     }
// }

// Define a trait for the callback to make it more flexible
pub trait MenderCallback {
    fn call<'a>(
        &'a self,
        type_str: Option<&'a str>,
        meta: Option<&'a str>,
        file: Option<&'a str>,
        size: usize,
        data: &'a [u8],
        offset: usize,
        total: usize,
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
    ) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'a>>;
}
