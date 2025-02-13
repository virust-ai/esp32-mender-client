#[cfg(any(feature = "esp32", feature = "esp32s2"))]
macro_rules! soc_address_in_bus {
    ($bus_name:ident, $vaddr:ident) => {{
        $vaddr >= concat_idents!($bus_name, _ADDRESS_LOW)
            && $vaddr < concat_idents!($bus_name, _ADDRESS_HIGH)
    }};
}

#[cfg(feature = "esp32")]
mod esp32;
#[cfg(feature = "esp32")]
pub use esp32::*;

#[cfg(feature = "esp32s2")]
mod esp32s2;
#[cfg(feature = "esp32s2")]
pub use esp32s2::*;

#[cfg(feature = "esp32s3")]
mod esp32s3;
#[cfg(feature = "esp32s3")]
pub use esp32s3::*;

#[cfg(feature = "esp32c2")]
mod esp32c2;
#[cfg(feature = "esp32c2")]
pub use esp32c2::*;

#[cfg(feature = "esp32c3")]
mod esp32c3;
#[cfg(feature = "esp32c3")]
pub use esp32c3::*;

#[cfg(feature = "esp32c6")]
mod esp32c6;
#[cfg(feature = "esp32c6")]
pub use esp32c6::*;

#[cfg(feature = "esp32h2")]
mod esp32h2;
#[cfg(feature = "esp32h2")]
pub use esp32h2::*;

#[cfg(not(any(
    feature = "esp32",
    feature = "esp32s2",
    feature = "esp32s3",
    feature = "esp32c2",
    feature = "esp32c3",
    feature = "esp32c6",
    feature = "esp32h2"
)))]
mod not_selected;

#[cfg(not(any(
    feature = "esp32",
    feature = "esp32s2",
    feature = "esp32s3",
    feature = "esp32c2",
    feature = "esp32c3",
    feature = "esp32c6",
    feature = "esp32h2"
)))]
pub use not_selected::*;
