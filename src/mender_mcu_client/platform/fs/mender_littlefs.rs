use crate::mender_mcu_client::core::mender_utils::{MenderResult, MenderStatus};
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::{ffi::CString, vec::Vec};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embedded_storage::{ReadStorage, Storage};
use esp_storage::FlashStorage;
use littlefs2::{
    consts::{U1, U512},
    driver::Storage as LfsStorage,
    fs::{Allocation, Filesystem},
    io::Error as LfsError,
    path::Path,
};

const PART_OFFSET: u32 = 0x8000;
const PART_SIZE: u32 = 0xc00;
const LITTLEFS_PART_SUBTYPE: u8 = 131; // LittleFS partition subtype

// Flash sector size for ESP32
const SECTOR_SIZE: usize = 4096;

#[derive(Debug)]
pub struct LittleFsInfo {
    pub offset: u32,
    pub size: u32,
}

// Adapter to make FlashStorage compatible with littlefs2 Storage trait
pub struct FlashStorageAdapter {
    flash: FlashStorage,
    offset: u32,
    size: u32,
}

// Implement Send for FlashStorageAdapter
unsafe impl Send for FlashStorageAdapter {}

impl FlashStorageAdapter {
    pub fn new(flash: FlashStorage, offset: u32, size: u32) -> Self {
        Self {
            flash,
            offset,
            size,
        }
    }
}

impl LfsStorage for FlashStorageAdapter {
    // Define cache and lookahead sizes
    type CACHE_SIZE = U512;
    type LOOKAHEAD_SIZE = U1;

    // Define read, write, and block sizes
    const READ_SIZE: usize = 16;
    const WRITE_SIZE: usize = 512;
    const BLOCK_SIZE: usize = 512;
    const BLOCK_COUNT: usize = 128; // Changed from 0 to a reasonable value

    fn read(&mut self, off: usize, buf: &mut [u8]) -> littlefs2::io::Result<usize> {
        // Check if the read operation is within bounds
        if off + buf.len() > self.size as usize {
            log_error!(
                "Read operation out of bounds: off={}, len={}, size={}",
                off,
                buf.len(),
                self.size
            );
            return Err(LfsError::IO);
        }

        self.flash
            .read(self.offset + off as u32, buf)
            .map_err(|e| {
                log_error!(
                    "Flash read error at offset {}: {:?}",
                    self.offset + off as u32,
                    e
                );
                LfsError::IO
            })?;
        Ok(buf.len())
    }

    fn write(&mut self, off: usize, data: &[u8]) -> littlefs2::io::Result<usize> {
        // Check if the write operation is within bounds
        if off + data.len() > self.size as usize {
            log_error!(
                "Write operation out of bounds: off={}, len={}, size={}",
                off,
                data.len(),
                self.size
            );
            return Err(LfsError::IO);
        }

        self.flash
            .write(self.offset + off as u32, data)
            .map_err(|e| {
                log_error!(
                    "Flash write error at offset {}: {:?}",
                    self.offset + off as u32,
                    e
                );
                LfsError::IO
            })?;
        Ok(data.len())
    }

    fn erase(&mut self, off: usize, len: usize) -> littlefs2::io::Result<usize> {
        // Check if the erase operation is within bounds
        if off + len > self.size as usize {
            log_error!(
                "Erase operation out of bounds: off={}, len={}, size={}",
                off,
                len,
                self.size
            );
            return Err(LfsError::IO);
        }

        // ESP32 flash requires sector-aligned erases
        let start_sector = off / SECTOR_SIZE;
        let end_sector = (off + len).div_ceil(SECTOR_SIZE);

        for _sector in start_sector..end_sector {
            // Use the Storage trait's erase method from embedded_storage
            // Note: FlashStorage doesn't have an erase method, so we'll use a different approach
            // This is a placeholder - you'll need to implement the actual erase functionality
            log_warn!("Erase operation not implemented for FlashStorage");
        }
        Ok(len)
    }
}

pub struct MenderLittleFs {
    fs_info: LittleFsInfo,
}

impl MenderLittleFs {
    pub fn new(mut flash: FlashStorage) -> MenderResult<Self> {
        // Read partition info first
        let (_, fs_info) = Self::read_littlefs_partition(&mut flash)?;

        log_info!(
            "LittleFS partition offset: {} with size: {}",
            fs_info.offset,
            fs_info.size
        );

        Ok((MenderStatus::Ok, MenderLittleFs { fs_info }))
    }

    fn read_littlefs_partition(flash: &mut FlashStorage) -> MenderResult<LittleFsInfo> {
        let mut fs_info = LittleFsInfo { offset: 0, size: 0 };

        let mut bytes = [0xFF; 32];
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
            let p_name = core::str::from_utf8(&bytes[12..28]).unwrap();
            let p_flags = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
            log_info!(
                "{:?} {} {} {} {} {} {}",
                magic,
                p_type,
                p_subtype,
                p_offset,
                p_size,
                p_name,
                p_flags
            );

            if *p_type == 1 && *p_subtype == LITTLEFS_PART_SUBTYPE {
                fs_info.offset = p_offset;
                fs_info.size = p_size;
            }
        }

        if fs_info.offset != 0 && fs_info.size != 0 {
            log_info!(
                "LittleFS partition found at offset: {}, size: {}",
                fs_info.offset,
                fs_info.size
            );
            Ok((MenderStatus::Ok, fs_info))
        } else {
            log_error!("LittleFS partition not found");
            Err(MenderStatus::Failed)
        }
    }

    // Create a filesystem instance for the current operation
    fn with_filesystem<F, T>(&self, operation: F) -> Result<T, MenderStatus>
    where
        F: FnOnce(&Filesystem<FlashStorageAdapter>) -> Result<T, MenderStatus>,
    {
        // Create a new FlashStorage instance
        let flash = FlashStorage::new();

        let mut adapter = FlashStorageAdapter::new(flash, self.fs_info.offset, self.fs_info.size);
        let mut allocation = Allocation::new();

        // Try to mount the filesystem
        match Filesystem::mount(&mut allocation, &mut adapter) {
            Ok(fs) => {
                // Execute the operation with the mounted filesystem
                operation(&fs)
            }
            Err(e) => {
                log_error!("Failed to mount LittleFS: {:?}", e);

                // Try to format and mount
                // First format the storage
                // Create a new FlashStorage instance since the previous one was moved
                let flash2 = FlashStorage::new();
                let mut adapter =
                    FlashStorageAdapter::new(flash2, self.fs_info.offset, self.fs_info.size);
                let mut allocation = Allocation::new();

                // Format the storage
                match Filesystem::format(&mut adapter) {
                    Ok(_) => {
                        // Now try to mount again
                        match Filesystem::mount(&mut allocation, &mut adapter) {
                            Ok(fs) => {
                                // Execute the operation with the formatted filesystem
                                operation(&fs)
                            }
                            Err(e) => {
                                log_error!("Failed to mount after format: {:?}", e);
                                Err(MenderStatus::Failed)
                            }
                        }
                    }
                    Err(e) => {
                        log_error!("Failed to format LittleFS: {:?}", e);
                        Err(MenderStatus::Failed)
                    }
                }
            }
        }
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, MenderStatus> {
        self.with_filesystem(|fs| {
            // Convert path to a C string
            let path_cstr = CString::new(path).unwrap();
            let path = Path::from_cstr(path_cstr.as_c_str()).unwrap();

            // Use open_file_and_then instead of open_file
            match fs.open_file_and_then(path, |file| {
                // Create a buffer to store the file contents
                let mut buffer = Vec::new();
                let mut temp_buf = [0u8; 128]; // Use a fixed-size buffer for reading

                // Read the file in chunks
                loop {
                    match file.read(&mut temp_buf) {
                        Ok(0) => break, // End of file
                        Ok(n) => buffer.extend_from_slice(&temp_buf[..n]),
                        Err(e) => {
                            log_error!("Error reading file: {:?}", e);
                            return Err(LfsError::IO);
                        }
                    }
                }

                Ok(buffer)
            }) {
                Ok(buffer) => Ok(buffer),
                Err(e) => {
                    log_error!("Failed to read file: {}, error: {:?}", path, e);
                    Err(MenderStatus::Failed)
                }
            }
        })
    }

    pub fn write_file(&self, path: &str, data: &[u8]) -> Result<(), MenderStatus> {
        self.with_filesystem(|fs| {
            // Convert path to a C string
            let path_cstr = CString::new(path).unwrap();
            let path = Path::from_cstr(path_cstr.as_c_str()).unwrap();

            // Use create_file_and_then instead of create_file
            match fs.create_file_and_then(path, |file| {
                // Write the data in chunks
                let mut remaining = data;
                while !remaining.is_empty() {
                    match file.write(remaining) {
                        Ok(0) => return Err(LfsError::IO), // No bytes written, error
                        Ok(n) => remaining = &remaining[n..],
                        Err(e) => {
                            log_error!("Error writing file: {:?}", e);
                            return Err(e);
                        }
                    }
                }
                Ok(())
            }) {
                Ok(_) => Ok(()),
                Err(e) => {
                    log_error!("Failed to write file: {}, error: {:?}", path, e);
                    Err(MenderStatus::Failed)
                }
            }
        })
    }

    pub fn delete_file(&self, path: &str) -> Result<(), MenderStatus> {
        self.with_filesystem(|fs| {
            // Convert path to a C string
            let path_cstr = CString::new(path).unwrap();
            let path = Path::from_cstr(path_cstr.as_c_str()).unwrap();

            // Use remove instead of remove_file
            match fs.remove(path) {
                Ok(_) => Ok(()),
                Err(e) => {
                    log_error!("Failed to delete file: {}, error: {:?}", path, e);
                    Err(MenderStatus::Failed)
                }
            }
        })
    }
}

// Global instance - now just stores the partition info, not the filesystem
static MENDER_FS: Mutex<CriticalSectionRawMutex, Option<MenderLittleFs>> = Mutex::new(None);

// Public interface functions
pub async fn mender_fs_init() -> MenderResult<()> {
    let flash = FlashStorage::new();

    let (_, fs) = match MenderLittleFs::new(flash) {
        Ok(result) => result,
        Err(e) => {
            log_error!("Failed to create MenderLittleFs instance, error: {:?}", e);
            return Err(MenderStatus::Failed);
        }
    };

    let mut fs_mutex = MENDER_FS.lock().await;
    *fs_mutex = Some(fs);
    Ok((MenderStatus::Ok, ()))
}

pub async fn mender_fs_read_file(path: &str) -> MenderResult<Vec<u8>> {
    let fs_mutex = MENDER_FS.lock().await;
    if let Some(fs) = fs_mutex.as_ref() {
        match fs.read_file(path) {
            Ok(data) => Ok((MenderStatus::Ok, data)),
            Err(e) => Err(e),
        }
    } else {
        log_error!("Filesystem not initialized");
        Err(MenderStatus::Failed)
    }
}

pub async fn mender_fs_write_file(path: &str, data: &[u8]) -> MenderResult<()> {
    let fs_mutex = MENDER_FS.lock().await;
    if let Some(fs) = fs_mutex.as_ref() {
        match fs.write_file(path, data) {
            Ok(_) => Ok((MenderStatus::Ok, ())),
            Err(e) => Err(e),
        }
    } else {
        log_error!("Filesystem not initialized");
        Err(MenderStatus::Failed)
    }
}

pub async fn mender_fs_delete_file(path: &str) -> MenderResult<()> {
    let fs_mutex = MENDER_FS.lock().await;
    if let Some(fs) = fs_mutex.as_ref() {
        match fs.delete_file(path) {
            Ok(_) => Ok((MenderStatus::Ok, ())),
            Err(e) => Err(e),
        }
    } else {
        log_error!("Filesystem not initialized");
        Err(MenderStatus::Failed)
    }
}
