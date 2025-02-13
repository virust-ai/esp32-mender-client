use super::helpers;
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use sha2::Sha256;

pub(crate) type Result<T> = core::result::Result<T, OtaError>;

#[derive(Debug, PartialEq)]
pub enum OtaError {
    NotEnoughPartitions,
    OtaNotStarted,
    FlashRWError,
    WrongCRC,
    WrongOTAPArtitionOrder,
    OtaVerifyError,
    CannotFindCurrentBootPartition,
    InvalidChecksum,
}

#[derive(Clone)]
pub struct FlashProgress {
    pub last_hash: Sha256,
    pub flash_offset: u32,
    pub flash_size: u32,
    pub remaining: u32,

    pub target_partition: u32,
    pub target_hash: [u8; 32],
}

#[derive(Debug)]
pub struct PartitionInfo {
    pub ota_partitions: [(u32, u32); 16],
    pub ota_partitions_count: u32,

    pub otadata_offset: u32,
    pub otadata_size: u32,
}

#[repr(u32)]
#[derive(Debug, PartialEq, Clone, Copy)]
#[allow(clippy::enum_variant_names)]
pub enum OtaImgState {
    EspOtaImgNew = 0x0,
    #[allow(dead_code)]
    EspOtaImgPendingVerify = 0x1,
    EspOtaImgValid = 0x2,
    EspOtaImgInvalid = 0x3,
    EspOtaImgAborted = 0x4,
    EspOtaImgUndefined = u32::MAX,
}

#[repr(C)]
#[derive(Debug)]
pub struct EspOtaSelectEntry {
    pub seq: u32,
    pub seq_label: [u8; 20],
    pub ota_state: OtaImgState,
    pub crc: u32,
}

impl EspOtaSelectEntry {
    pub fn check_crc(&mut self) {
        if !helpers::is_crc_seq_correct(self.seq, self.crc) {
            self.seq = 0; // set seq to 0 if crc not correct!
        }
    }
}
