use embedded_storage::{ReadStorage, Storage};
use sha2::{Sha256, Digest};
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};

pub use structs::*;

pub mod crc32;
pub mod helpers;
pub mod mmu_hal;
pub mod mmu_ll;
pub mod structs;

const PART_OFFSET: u32 = 0x8000;
const PART_SIZE: u32 = 0xc00;
const FIRST_OTA_PART_SUBTYPE: u8 = 0x10;
const OTA_VERIFY_READ_SIZE: usize = 256;

// NOTE: I need to use generics, because after adding esp-storage dependency to
// this project its not compiling LULE
pub struct Ota<S>
where
    S: ReadStorage + Storage,
{
    flash: S,

    progress: Option<FlashProgress>,
    pinfo: PartitionInfo,
}

impl<S> Ota<S>
where
    S: ReadStorage + Storage,
{
    pub fn new(mut flash: S) -> Result<Self> {
        let pinfo = Self::read_partitions(&mut flash)?;
        if pinfo.ota_partitions_count < 2 {
            log_error!("Not enough OTA partitions! (>= 2)");
            return Err(OtaError::NotEnoughPartitions);
        }

        Ok(Ota {
            flash,
            progress: None,
            pinfo,
        })
    }

    fn get_partitions(&self) -> &[(u32, u32)] {
        &self.pinfo.ota_partitions[..self.pinfo.ota_partitions_count]
    }

    /// To begin ota update (need to provide flash size)
    pub fn ota_begin(&mut self, size: u32, chksum: &[u8]) -> Result<()> {
        let next_part = self.get_next_ota_partition().unwrap_or(0);

        // Convert hex string to bytes
        let chksum_str = core::str::from_utf8(chksum)
            .map_err(|_| OtaError::InvalidChecksum)?;
        
        let mut target_hash = [0u8; 32];
        for i in 0..32 {
            let byte_str = &chksum_str[i*2..i*2+2];
            target_hash[i] = u8::from_str_radix(byte_str, 16)
                .map_err(|_| OtaError::InvalidChecksum)?;
        }

        log_info!("[OTA] Received hash: ", "target_hash" => target_hash);

        let ota_offset = self.get_partitions()[next_part].0;
        self.progress = Some(FlashProgress {
            last_hash: Sha256::new(),
            flash_size: size,
            remaining: size,
            flash_offset: ota_offset,
            target_partition: next_part,
            target_hash,
        });

        Ok(())
    }

    pub fn ota_abort(&mut self) -> Result<()> {
        let progress = self
            .progress
            .clone()
            .ok_or(OtaError::OtaNotStarted)?;

        self.set_ota_state((progress.target_partition + 1) as u8, OtaImgState::EspOtaImgAborted)?;
        self.progress = None;
        log_info!("[OTA] OTA aborted");
        Ok(())

    }


    /// Returns ota progress in f32 (0..1)
    #[allow(dead_code)]
    pub fn get_ota_progress(&self) -> f32 {
        if self.progress.is_none() {
            log_warn!("[OTA] Cannot get ota progress! Seems like update wasn't started yet.");

            return 0.0;
        }

        let progress = self.progress.as_ref().unwrap();
        (progress.flash_size - progress.remaining) as f32 / progress.flash_size as f32
    }

    /// Writes next firmware chunk
    pub fn ota_write_chunk(&mut self, chunk: &[u8], length: usize) -> Result<bool> {
        let progress = self
            .progress
            .as_mut()
            .ok_or(OtaError::OtaNotStarted)?;

        if progress.remaining == 0 {
            return Ok(true);
        }

        if length as u32 > progress.remaining {
            log::error!("[OTA] Write size exceeds remaining size");
            return Err(OtaError::FlashRWError);
        }

        //let write_size = chunk.len() as u32;
        let write_size = length as u32;
        let write_size = write_size.min(progress.remaining) as usize;

        // // Log chunk details
        // log_info!(
        //     "[OTA] Writing chunk: ",
        //     "flash_offset" => progress.flash_offset,
        //     "write_size" => write_size,
        //     "remaining" => progress.remaining
        // );


        // // Log first chunk's bytes
        // if progress.flash_offset == self.pinfo.ota_partitions[progress.target_partition].0 {
        //     log_info!("[OTA] First chunk bytes: ", "chunk" => &chunk[..16.min(write_size)]);
        // }
    

        // // Log last chunk's bytes
        // if progress.remaining <= write_size as u32 {
        //     log::info!("[OTA] Last chunk bytes: {:02x?}", &chunk[write_size.saturating_sub(16)..write_size]);
        // }

        self.flash
            .write(progress.flash_offset, &chunk[..write_size])
            .map_err(|_| OtaError::FlashRWError)?;

        progress.last_hash.update(&chunk[..write_size]);
        progress.flash_offset += write_size as u32;
        progress.remaining -= write_size as u32;

        Ok(progress.remaining == 0)
    }

    /// verify - should it read flash and check crc
    pub fn ota_flush(&mut self, verify: bool) -> Result<()> {
        if verify && !self.ota_verify()? {
            log_error!("[OTA] Verify failed! Not flushing...");

            return Err(OtaError::OtaVerifyError);
        }

        let progress = self
            .progress
            .clone()
            .ok_or(OtaError::OtaNotStarted)?;

        if progress.target_hash != progress.last_hash.clone().finalize().as_slice() {
 
            log_warn!("[OTA] Calculated hash: ", "hash" => progress.last_hash);
            log_warn!("[OTA] Target hash: ", "hash" => progress.target_hash);
            log_error!("[OTA] Crc check failed! Cant finish ota update...");

            return Err(OtaError::WrongCRC);
        }

        log_info!("[OTA] OTA flush completed successfully");
        Ok(())
    }

    /// rollback - if rollbacks enable (will set ota_state to ESP_OTA_IMG_NEW)
    pub fn ota_set_pending_image(&mut self, rollback: bool) -> Result<()> {
        let progress = self
            .progress
            .clone()
            .ok_or(OtaError::OtaNotStarted)?;

        let img_state = match rollback {
            true => OtaImgState::EspOtaImgNew,
            false => OtaImgState::EspOtaImgUndefined,
        };

        // Then set it as the boot partition
        self.set_target_ota_boot_partition(progress.target_partition, img_state);

        // // Verify the settings were applied
        // let (slot1, slot2) = self.get_ota_boot_entries();
        // let target_part = helpers::seq_to_part(slot1.seq.max(slot2.seq), self.pinfo.ota_partitions_count);
        
        // if target_part != progress.target_partition {
        //     log_error!("[OTA] Failed to set boot partition", 
        //         "expected" => progress.target_partition,
        //         "actual" => target_part);
        //     return Err(OtaError::FlashRWError);
        // }

        log_info!("[OTA] OTA set pending image", 
            "target_partition" => progress.target_partition, 
            "img_state" => img_state);
        Ok(())
    }

    /// It reads written flash and checks crc
    pub fn ota_verify(&mut self) -> Result<bool> {
        let progress = self
            .progress
            .clone()
            .ok_or(OtaError::OtaNotStarted)?;

        let mut hasher = Sha256::new();
        let mut bytes = [0; OTA_VERIFY_READ_SIZE];

        let mut partition_offset = self.pinfo.ota_partitions[progress.target_partition].0;
        let mut remaining = progress.flash_size;

        // Add debug logging
        log_info!("[OTA] Starting verification from offset: ", "offset" => format_args!("0x{:x}", partition_offset));
        log_info!("[OTA] Total size to verify: ", "size" => remaining);
        log_info!("[OTA] Target partition: ", "partition" => progress.target_partition);


        // // Read and log first bytes
        // if remaining > 0 {
        //     let n = remaining.min(OTA_VERIFY_READ_SIZE as u32);
        //     _ = self.flash.read(partition_offset, &mut bytes[..n as usize]);
        //     log_info!("[OTA] First bytes read back: ", "bytes" => &bytes[..16.min(n as usize)]);
        // }


        // Read all data for hash calculation
        while remaining > 0 {
            let n = remaining.min(OTA_VERIFY_READ_SIZE as u32);
            _ = self.flash.read(partition_offset, &mut bytes[..n as usize]);
            
            // // Log last chunk's bytes
            // if remaining <= n {
            //     log_info!("[OTA] Last bytes read back: ", "bytes" => &bytes[n.saturating_sub(16) as usize..n as usize]);
            // }
            

            partition_offset += n;
            remaining -= n;
            hasher.update(&bytes[..n as usize]);
        }

        let computed_hash = hasher.finalize();

        log_warn!("[OTA] Write hash: ", "hash" => progress.last_hash.finalize().as_slice());
        log_warn!("[OTA] Read hash: ", "hash" => computed_hash.as_slice());
        log_warn!("[OTA] Target hash: ", "hash" => progress.target_hash);


        Ok(computed_hash[..] == progress.target_hash[..])
    }

    /// Sets ota boot target partition
    pub fn set_target_ota_boot_partition(&mut self, target: usize, state: OtaImgState) {
        let (slot1, slot2) = self.get_ota_boot_entries();
        let (seq1, seq2) = (slot1.seq, slot2.seq);

        let mut target_seq = seq1.max(seq2);
        while helpers::seq_to_part(target_seq, self.pinfo.ota_partitions_count) != target
            || target_seq == 0
        {
            target_seq += 1;
        }

        let mut entry1 = [0u8; 32];
        let mut entry2 = [0u8; 32];
        let target_crc = crc32::calc_crc32(&target_seq.to_le_bytes(), 0xFFFFFFFF);
    
        if target_seq == 2 {
            log_info!("[OTA] Setting target ota boot partition to ota_1");
            // First slot: seq=2 (higher than current)
            entry1[0..4].copy_from_slice(&target_seq.to_le_bytes());
            entry1[4..24].fill(0xFF);
            entry1[24..28].copy_from_slice(&(state as u32).to_le_bytes());            
            entry1[28..32].copy_from_slice(&target_crc.to_le_bytes());

            // Second slot: seq=1 (for current ota_0)
            entry2[0..4].copy_from_slice(&(target_seq - 1).to_le_bytes());
            entry2[4..24].fill(0xFF);
            entry2[24..28].copy_from_slice(&(OtaImgState::EspOtaImgValid as u32).to_le_bytes());
            let crc2 = crc32::calc_crc32(&(target_seq - 1).to_le_bytes(), 0xFFFFFFFF);
            entry2[28..32].copy_from_slice(&crc2.to_le_bytes());

        } else {
            log_info!("[OTA] Setting target ota boot partition to ota_0");
            // For ota_0, use lower sequence
            entry1[0..4].copy_from_slice(&target_seq.to_le_bytes());
            entry1[4..24].fill(0xFF);
            entry1[24..28].copy_from_slice(&(state as u32).to_le_bytes());
            entry1[28..32].copy_from_slice(&target_crc.to_le_bytes());

            entry2.fill(0xFF);  // Second slot invalid
        }

        let flash = &mut self.flash;     

        // Write entries
        _ = flash.write(self.pinfo.otadata_offset, &entry1);
        _ = flash.write(self.pinfo.otadata_offset + (self.pinfo.otadata_size >> 1), &entry2);

        log_info!("[OTA] Writing boot entries for target partition", 
            "target" => target,
            "offset1" => format_args!("0x{:x}", self.pinfo.otadata_offset),
            "offset2" => format_args!("0x{:x}", self.pinfo.otadata_offset + (self.pinfo.otadata_size >> 1)));

        // Verify the writes
        let mut verify_buf = [0u8; 32];
        
        // Verify slot 1
        _ = flash.read(self.pinfo.otadata_offset, &mut verify_buf);
        log_info!("[OTA] Slot 1 verification", 
            "seq" => u32::from_le_bytes(verify_buf[0..4].try_into().unwrap()),
            "state" => format_args!("0x{:x}", u32::from_le_bytes(verify_buf[24..28].try_into().unwrap())),
            "crc" => format_args!("0x{:x}", u32::from_le_bytes(verify_buf[28..32].try_into().unwrap())));

        // Verify slot 2
        _ = flash.read(self.pinfo.otadata_offset + (self.pinfo.otadata_size >> 1), &mut verify_buf);
        log_info!("[OTA] Slot 2 verification", 
            "seq" => u32::from_le_bytes(verify_buf[0..4].try_into().unwrap()),
            "state" => format_args!("0x{:x}", u32::from_le_bytes(verify_buf[24..28].try_into().unwrap())),
            "crc" => format_args!("0x{:x}", u32::from_le_bytes(verify_buf[28..32].try_into().unwrap())));
    }

    pub fn set_ota_state(&mut self, slot: u8, state: OtaImgState) -> Result<()> {
        let offset = match slot {
            1 => self.pinfo.otadata_offset,
            2 => self.pinfo.otadata_offset + (self.pinfo.otadata_size >> 1),
            _ => {
                log_error!("Use slot1 or slot2!");
                return Err(OtaError::CannotFindCurrentBootPartition);
            }

        };

        _ = self
            .flash
            .write(offset + 32 - 4 - 4, &(state as u32).to_le_bytes());

        Ok(())
    }

    /// Returns current OTA boot sequences
    ///
    /// NOTE: if crc doesn't match, it returns 0 for that seq
    /// NOTE: [Entry struct (link to .h file)](https://github.com/espressif/esp-idf/blob/master/components/bootloader_support/include/esp_flash_partitions.h#L66)
    pub fn get_ota_boot_entries(&mut self) -> (EspOtaSelectEntry, EspOtaSelectEntry) {
        let mut bytes = [0; 32];
        _ = self.flash.read(self.pinfo.otadata_offset, &mut bytes);
        let mut slot1: EspOtaSelectEntry =
            unsafe { core::ptr::read(bytes.as_ptr() as *const EspOtaSelectEntry) };
        slot1.check_crc();

        _ = self.flash.read(
            self.pinfo.otadata_offset + (self.pinfo.otadata_size >> 1),
            &mut bytes,
        );
        let mut slot2: EspOtaSelectEntry =
            unsafe { core::ptr::read(bytes.as_ptr() as *const EspOtaSelectEntry) };
        slot2.check_crc();

        (slot1, slot2)
    }

    /// Returns currently booted partition index
    pub fn get_currently_booted_partition(&self) -> Option<usize> {
        mmu_hal::esp_get_current_running_partition(self.get_partitions())
    }

    /// BUG: this wont work if user has ota partitions not starting from ota0
    /// or if user skips some ota partitions: ota0, ota2, ota3...
    pub fn get_next_ota_partition(&self) -> Option<usize> {
        let curr_part = mmu_hal::esp_get_current_running_partition(self.get_partitions());
        curr_part.map(|next_part| (next_part + 1) % self.pinfo.ota_partitions_count)
    }

    fn get_current_slot(&mut self) -> Result<(u8, EspOtaSelectEntry)> {
        let (slot1, slot2) = self.get_ota_boot_entries();
        let current_partition = self
            .get_currently_booted_partition()
            .ok_or(OtaError::CannotFindCurrentBootPartition)?;

        let slot1_part = helpers::seq_to_part(slot1.seq, self.pinfo.ota_partitions_count);
        let slot2_part = helpers::seq_to_part(slot2.seq, self.pinfo.ota_partitions_count);
        if current_partition == slot1_part {
            return Ok((1, slot1));
        } else if current_partition == slot2_part {
            return Ok((2, slot2));
        }

        Err(OtaError::CannotFindCurrentBootPartition)
    }

    pub fn get_ota_image_state(&mut self) -> Result<OtaImgState> {
        let (slot1, slot2) = self.get_ota_boot_entries();
        let current_partition = self
            .get_currently_booted_partition()
            .ok_or(OtaError::CannotFindCurrentBootPartition)?;

        let slot1_part = helpers::seq_to_part(slot1.seq, self.pinfo.ota_partitions_count);
        let slot2_part = helpers::seq_to_part(slot2.seq, self.pinfo.ota_partitions_count);
        if current_partition == slot1_part {
            return Ok(slot1.ota_state);
        } else if current_partition == slot2_part {
            return Ok(slot2.ota_state);
        }

        Err(OtaError::CannotFindCurrentBootPartition)
    }

    pub fn ota_mark_app_valid(&mut self) -> Result<()> {
        let (current_slot_nmb, current_slot) = self.get_current_slot()?;
        if current_slot.ota_state != OtaImgState::EspOtaImgValid {
            self.set_ota_state(current_slot_nmb, OtaImgState::EspOtaImgValid)?;

            log_info!("Marked current slot as valid!", "current_slot_nmb" => current_slot_nmb, "current_slot" => current_slot);
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn ota_mark_app_invalid_rollback(&mut self) -> Result<()> {
        let (current_slot_nmb, current_slot) = self.get_current_slot()?;
        if current_slot.ota_state != OtaImgState::EspOtaImgValid {
            self.set_ota_state(current_slot_nmb, OtaImgState::EspOtaImgInvalid)?;

            log_info!("Marked current slot as invalid!");

        }

        Ok(())
    }

    fn read_partitions(flash: &mut S) -> Result<PartitionInfo> {
        let mut tmp_pinfo = PartitionInfo {
            ota_partitions: [(0, 0); 16],
            ota_partitions_count: 0,
            otadata_size: 0,
            otadata_offset: 0,
        };

        let mut bytes = [0xFF; 32];
        let mut last_ota_part: i8 = -1;
        for read_offset in (0..PART_SIZE).step_by(32) {
            _ = flash.read(PART_OFFSET + read_offset, &mut bytes);
            if bytes == [0xFF; 32] {
                break;
            }

            let magic = &bytes[0..2];
            if magic != [0xAA, 0x50] {
                continue;
            }

            let p_type = &bytes[2];
            let p_subtype = &bytes[3];
            let p_offset = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            let p_size = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            //let p_name = core::str::from_utf8(&bytes[12..28]).unwrap();
            //let p_flags = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
            //log::info!("{magic:?} {p_type} {p_subtype} {p_offset} {p_size} {p_name} {p_flags}");

            if *p_type == 0 && *p_subtype >= FIRST_OTA_PART_SUBTYPE {
                let ota_part_idx = *p_subtype - FIRST_OTA_PART_SUBTYPE;
                if ota_part_idx as i8 - last_ota_part != 1 {
                    return Err(OtaError::WrongOTAPArtitionOrder);
                }

                last_ota_part = ota_part_idx as i8;
                tmp_pinfo.ota_partitions[tmp_pinfo.ota_partitions_count] = (p_offset, p_size);
                tmp_pinfo.ota_partitions_count += 1;
            } else if *p_type == 1 && *p_subtype == 0 {
                //otadata
                tmp_pinfo.otadata_offset = p_offset;
                tmp_pinfo.otadata_size = p_size;
            }
        }

        Ok(tmp_pinfo)
    }
}