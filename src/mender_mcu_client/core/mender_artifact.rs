//use alloc::string::String;
use crate::{
    custom::mender_common::MenderCallback,
    mender_mcu_client::core::mender_utils::{MenderError, MenderResult},
};
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::format;
use heapless::{String as HString, Vec as HVec};
use serde::Deserialize;

#[derive(Debug, Clone, Copy)]
pub enum MenderArtifactStreamState {
    ParsingHeader, // Currently parsing header
    ParsingData,   // Currently parsing data
}

#[derive(Debug, serde::Deserialize)]
pub struct MenderArtifactPayload {
    #[serde(rename = "type")]
    pub payload_type: HString<MAX_STRING_SIZE>, // Type of the payload
    pub meta_data: Option<JsonResponse>, // Meta-data from header tarball
}

// Reuse the JsonResponse from mender_api.rs
#[derive(Debug, Deserialize)]
pub struct JsonResponse {
    pub error: Option<HString<100>>,
    // Add other fields that might be in the meta_data
}

impl JsonResponse {
    pub fn as_str(&self) -> &str {
        match &self.error {
            Some(err) => err.as_str(),
            None => "",
        }
    }
}

pub struct MenderArtifactContext {
    pub stream_state: MenderArtifactStreamState,
    pub input: MenderArtifactInput,
    pub payloads: MenderArtifactPayloads,
    pub file: MenderArtifactFile,
}

pub struct MenderArtifactInput {
    pub data: HVec<u8, 16384>, // Data received chunk by chunk
    pub length: usize,         // Length of data received
}

pub struct MenderArtifactPayloads {
    pub size: usize,                             // Number of payloads
    pub values: HVec<MenderArtifactPayload, 16>, // Values of payloads
}

pub struct MenderArtifactFile {
    pub name: HString<100>, // Name of file being parsed
    pub size: usize,        // Size of file in bytes
    pub index: usize,       // Current position in file
}

const MENDER_ARTIFACT_STREAM_BLOCK_SIZE: usize = 512;
const MENDER_ARTIFACT_VERSION_FORMAT: &str = "mender"; // Adjust value as needed
const MENDER_ARTIFACT_VERSION_VALUE: i32 = 3; // Adjust value as needed

#[repr(C, packed)]
struct TarHeader {
    name: [u8; 100],
    mode: [u8; 8],
    uid: [u8; 8],
    gid: [u8; 8],
    size: [u8; 12],
    mtime: [u8; 12],
    chksum: [u8; 8],
    typeflag: u8,
    linkname: [u8; 100],
    magic: [u8; 6],
    version: [u8; 2],
    uname: [u8; 32],
    gname: [u8; 32],
    devmajor: [u8; 8],
    devminor: [u8; 8],
    prefix: [u8; 155],
}

const MAX_STRING_SIZE: usize = 128; // Adjust as needed
const MAX_PAYLOADS: usize = 16;

#[derive(Debug, serde::Deserialize)]
struct VersionInfo<'a> {
    format: &'a str,
    version: i64,
}

#[derive(Debug, serde::Deserialize)]
pub struct HeaderInfo {
    pub payloads: HString<MAX_PAYLOADS>,
}

#[derive(Debug, serde::Deserialize)]
pub struct PayloadInfo {
    #[serde(rename = "type")]
    pub payload_type: HString<MAX_STRING_SIZE>,
}

impl MenderArtifactContext {
    pub fn new() -> Self {
        Self {
            stream_state: MenderArtifactStreamState::ParsingHeader,
            input: MenderArtifactInput {
                data: HVec::new(),
                length: 0,
            },
            payloads: MenderArtifactPayloads {
                size: 0,
                values: HVec::new(),
            },
            file: MenderArtifactFile {
                name: HString::new(),
                size: 0,
                index: 0,
            },
        }
    }
}

pub async fn mender_artifact_process_data(
    ctx: &mut MenderArtifactContext,
    input_data: Option<&[u8]>,
    input_length: usize,
    callback: Option<&(dyn MenderCallback + Send + Sync)>,
) -> MenderResult<()> {
    log_info!("mender_artifact_process_data");
    // Copy data to the end of the internal buffer
    if let Some(data) = input_data {
        if input_length > 0 {
            if ctx
                .input
                .data
                .extend_from_slice(&data[..input_length])
                .is_err()
            {
                log_error!("Failed to extend input data buffer");
                return Err(MenderError::Failed);
            }
            ctx.input.length += input_length;
        }
    }

    // Parse data
    loop {
        // Use 'break' directly in error cases
        match ctx.stream_state {
            MenderArtifactStreamState::ParsingHeader => {
                // Parse TAR header
                mender_artifact_parse_tar_header(ctx)?;
            }
            MenderArtifactStreamState::ParsingData => {
                // Treatment depending on the file name
                match ctx.file.name.as_str() {
                    "version" => {
                        mender_artifact_check_version(ctx)?;
                    }
                    "header.tar/header-info" => {
                        mender_artifact_read_header_info(ctx)?;
                    }
                    name if name.starts_with("header.tar/headers")
                        && name.ends_with("meta-data") =>
                    {
                        mender_artifact_read_meta_data(ctx)?;
                    }
                    name if name.starts_with("data") => {
                        mender_artifact_read_data(ctx, callback).await?;
                    }
                    name if !name.ends_with(".tar") => {
                        mender_artifact_drop_file(ctx)?;
                    }
                    _ => {
                        return Ok(());
                    }
                }

                // Check if file has been parsed and treatment done
                if ctx.file.name.rfind(".tar").is_some() {
                    if let Some(pos) = ctx.file.name.rfind(".tar") {
                        ctx.file.name.truncate(pos);
                    }
                    ctx.file.size = 0;
                    ctx.file.index = 0;

                    ctx.stream_state = MenderArtifactStreamState::ParsingHeader;
                }
            }
        }

        // If we need more data, break the loop
        if ctx.input.data.is_empty() || ctx.input.length < MENDER_ARTIFACT_STREAM_BLOCK_SIZE {
            break;
        }
    }

    Ok(())
}

impl Drop for MenderArtifactContext {
    fn drop(&mut self) {
        log::info!("Dropping MenderArtifactContext");

        // All memory will be automatically freed:
        // - Vec<u8> in input.data
        // - Vec<MenderArtifactPayload> in payloads.values
        // - String in file.name
        // - JsonResponse in meta_data
    }
}

pub fn mender_artifact_parse_tar_header(ctx: &mut MenderArtifactContext) -> MenderResult<()> {
    log_info!("mender_artifact_parse_tar_header");
    // Check if enough data are received (at least one block)
    if ctx.input.data.is_empty() || ctx.input.length < MENDER_ARTIFACT_STREAM_BLOCK_SIZE {
        return Ok(());
    }

    // Cast block to TAR header structure safely
    let tar_header = unsafe { &*(ctx.input.data.as_ptr() as *const TarHeader) };

    // Check if file name is provided, else the end of the current TAR file is reached
    if tar_header.name[0] == 0 {
        // Check if enough data are received (at least 2 blocks)
        if ctx.input.length < 2 * MENDER_ARTIFACT_STREAM_BLOCK_SIZE {
            return Ok(());
        }

        // Remove the TAR file name by truncating at last .tar
        if let Some(pos) = ctx.file.name.rfind(".tar") {
            ctx.file.name.truncate(pos);
            if let Some(pos) = ctx.file.name.rfind(".tar") {
                ctx.file.name.truncate(pos);
            }
        }

        // Shift data in the buffer
        if let Err(e) = mender_artifact_shift_data(ctx, 2 * MENDER_ARTIFACT_STREAM_BLOCK_SIZE) {
            log::error!("Unable to shift input data");
            return Err(e);
        }

        return Ok(());
    }

    // Check magic
    let magic = &tar_header.magic;
    if magic != b"ustar " {
        log::error!("Invalid magic");
        return Err(MenderError::Failed);
    }

    // Compute the new file name
    let header_name = core::str::from_utf8(&tar_header.name)
        .map_err(|_| MenderError::Failed)?
        .trim_matches('\0');

    ctx.file.name = format!("{}/{}", ctx.file.name, header_name)
        .as_str()
        .try_into()
        .map_err(|_| MenderError::Failed)?;

    // Retrieve file size (parse octal string)
    let size_str = core::str::from_utf8(&tar_header.size)
        .map_err(|_| MenderError::Failed)?
        .trim_matches('\0');
    ctx.file.size = usize::from_str_radix(size_str, 8).map_err(|_| MenderError::Failed)?;
    ctx.file.index = 0;

    // Shift data in the buffer
    if let Err(e) = mender_artifact_shift_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE) {
        log::error!("Unable to shift input data");
        return Err(e);
    }

    // Update the stream state machine
    ctx.stream_state = MenderArtifactStreamState::ParsingData;

    Ok(())
}

pub fn mender_artifact_check_version(ctx: &mut MenderArtifactContext) -> MenderResult<()> {
    // Check if all data have been received
    if ctx.input.data.is_empty()
        || ctx.input.length
            < mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)
    {
        return Ok(());
    }

    // Parse version file
    let (version_info, _): (VersionInfo, _) =
        serde_json_core::from_slice(&ctx.input.data[..ctx.file.size]).map_err(|_| {
            log::error!("Unable to parse version file");
            MenderError::Failed
        })?;

    // Check format
    if version_info.format != MENDER_ARTIFACT_VERSION_FORMAT {
        log::error!("Invalid version format");
        return Err(MenderError::Failed);
    }

    // Check version
    if version_info.version != MENDER_ARTIFACT_VERSION_VALUE as i64 {
        log::error!("Invalid version value");
        return Err(MenderError::Failed);
    }

    log::info!("Artifact has valid version");

    // Shift data in the buffer
    if let Err(e) = mender_artifact_shift_data(
        ctx,
        mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE),
    ) {
        log::error!("Unable to shift input data");
        return Err(e);
    }

    Ok(())
}

pub fn mender_artifact_read_header_info(ctx: &mut MenderArtifactContext) -> MenderResult<()> {
    // Check if all data have been received
    if ctx.input.data.is_empty()
        || ctx.input.length
            < mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)
    {
        return Ok(());
    }

    // Read and parse header-info
    let (header_info, _): (HeaderInfo, _) =
        serde_json_core::from_slice(&ctx.input.data[..ctx.file.size]).map_err(|_| {
            log::error!("Unable to parse header-info");
            MenderError::Failed
        })?;

    // Set payloads size and create new vector
    ctx.payloads.size = header_info.payloads.len();
    ctx.payloads.values = HVec::new();

    // Create new payload entry
    let payload_type: HString<MAX_STRING_SIZE> = header_info
        .payloads
        .as_str()
        .try_into()
        .map_err(|_| MenderError::Failed)?;

    // Handle the Result from push operation
    if ctx
        .payloads
        .values
        .push(MenderArtifactPayload {
            payload_type,
            meta_data: None,
        })
        .is_err()
    {
        log_error!("Failed to push payload to values vector");
        return Err(MenderError::Failed);
    }

    // Shift data in the buffer
    if let Err(e) = mender_artifact_shift_data(
        ctx,
        mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE),
    ) {
        log::error!("Unable to shift input data");
        return Err(e);
    }

    Ok(())
}

pub fn mender_artifact_read_meta_data(ctx: &mut MenderArtifactContext) -> MenderResult<()> {
    // Retrieve payload index from filename using string operations
    let index = {
        let name = &ctx.file.name;
        if !name.starts_with("header.tar/headers/") || !name.ends_with("/meta-data") {
            log::error!("Invalid artifact format");
            return Err(MenderError::Failed);
        }

        let start = "header.tar/headers/".len();
        let end = name[start..].find('/').ok_or_else(|| {
            log::error!("Invalid artifact format");
            MenderError::Failed
        })?;

        let index_str = &name[start..start + end];
        let index = index_str.parse::<usize>().map_err(|_| {
            log::error!("Invalid artifact format");
            MenderError::Failed
        })?;

        if index >= ctx.payloads.size {
            log::error!("Invalid artifact format");
            return Err(MenderError::Failed);
        }
        index
    };

    // Check size of the meta-data
    if mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE) == 0 {
        // Nothing to do
        return Ok(());
    }

    // Check if all data have been received
    if ctx.input.data.is_empty()
        || ctx.input.length
            < mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)
    {
        return Ok(());
    }

    // Read meta-data
    let (meta_data, _): (JsonResponse, _) =
        serde_json_core::from_slice(&ctx.input.data[..ctx.file.size]).map_err(|_| {
            log::error!("Unable to parse meta-data");
            MenderError::Failed
        })?;

    ctx.payloads.values[index].meta_data = Some(meta_data);

    // Shift data in the buffer
    if let Err(e) = mender_artifact_shift_data(
        ctx,
        mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE),
    ) {
        log::error!("Unable to shift input data");
        return Err(e);
    }

    Ok(())
}

pub async fn mender_artifact_read_data(
    ctx: &mut MenderArtifactContext,
    callback: Option<&(dyn MenderCallback + Send + Sync)>,
) -> MenderResult<()> {
    log_info!("mender_artifact_read_data");
    // Retrieve payload index using string operations
    let index = {
        let name = &ctx.file.name;
        if !name.starts_with("data/") || !name.ends_with(".tar") {
            log::error!("Invalid artifact format");
            return Err(MenderError::Failed);
        }

        let start = "data/".len();
        let end = name[start..].find('.').ok_or_else(|| {
            log::error!("Invalid artifact format");
            MenderError::Failed
        })?;

        let index_str = &name[start..start + end];
        let index = index_str.parse::<usize>().map_err(|_| {
            log::error!("Invalid artifact format");
            MenderError::Failed
        })?;

        if index >= ctx.payloads.size {
            log::error!("Invalid artifact format");
            return Err(MenderError::Failed);
        }
        index
    };

    // Check if a file name is provided
    if ctx.file.name.len() == "data/xxxx.tar".len() {
        log_info!("mender_artifact_read_data: Beginning of the data file");
        if let Some(callback_fn) = callback {
            callback_fn
                .call(
                    Some(ctx.payloads.values[index].payload_type.as_str()), // Convert to Option<&str>
                    Some(
                        ctx.payloads.values[index]
                            .meta_data
                            .as_ref()
                            .unwrap()
                            .as_str(),
                    ), // Convert to Option<&str>
                    None, // Other arguments remain as is
                    0,
                    b"",
                    0,
                    0,
                )
                .await?;
        } else {
            log_error!("Invalid callback");
            return Err(MenderError::Failed);
        }
    }

    // Check size of the data
    if mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE) == 0 {
        // Nothing to do
        return Ok(());
    }

    // Parse data until the end of the file has been reached
    while ctx.file.index < ctx.file.size {
        // Check if enough data are received (at least one block)
        if ctx.input.data.is_empty() || ctx.input.length < MENDER_ARTIFACT_STREAM_BLOCK_SIZE {
            return Ok(());
        }

        // Compute length for this block
        let block_length = (ctx.file.size - ctx.file.index).min(MENDER_ARTIFACT_STREAM_BLOCK_SIZE);

        // Get filename after .tar
        let filename = ctx
            .file
            .name
            .split(".tar")
            .nth(1)
            .map(|s| &s[1..])
            .unwrap_or(""); // Provide default empty string if None

        // Invoke callback
        if let Some(callback_fn) = callback {
            callback_fn
                .call(
                    Some(&ctx.payloads.values[index].payload_type),
                    Some(
                        ctx.payloads.values[index]
                            .meta_data
                            .as_ref()
                            .unwrap()
                            .as_str(),
                    ),
                    Some(filename),
                    ctx.file.size,
                    &ctx.input.data,
                    ctx.file.index,
                    block_length,
                )
                .await?;
        } else {
            log_error!("Invalid callback");
            return Err(MenderError::Failed);
        }

        // Update index
        ctx.file.index += MENDER_ARTIFACT_STREAM_BLOCK_SIZE;

        // Shift data in the buffer
        if let Err(e) = mender_artifact_shift_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE) {
            log::error!("Unable to shift input data");
            return Err(e);
        }
    }

    Ok(())
}

pub fn mender_artifact_drop_file(ctx: &mut MenderArtifactContext) -> MenderResult<()> {
    // Check size of the data
    if mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE) == 0 {
        // Nothing to do
        return Ok(());
    }

    // Parse data until the end of the file has been reached
    while ctx.file.index < ctx.file.size {
        // Check if enough data are received (at least one block)
        if ctx.input.data.is_empty() || ctx.input.length < MENDER_ARTIFACT_STREAM_BLOCK_SIZE {
            return Ok(());
        }

        // Update index
        ctx.file.index += MENDER_ARTIFACT_STREAM_BLOCK_SIZE;

        // Shift data in the buffer
        if let Err(e) = mender_artifact_shift_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE) {
            log::error!("Unable to shift input data");
            return Err(e);
        }
    }

    Ok(())
}

pub fn mender_artifact_shift_data(
    ctx: &mut MenderArtifactContext,
    length: usize,
) -> MenderResult<()> {
    if length > 0 {
        if ctx.input.length > length {
            // Shift remaining data to front of vector
            ctx.input.data.copy_within(length.., 0);
            // Truncate vector to new length
            ctx.input.data.truncate(ctx.input.length - length);
            ctx.input.length -= length;
        } else {
            // Clear all data
            ctx.input.data.clear();
            ctx.input.length = 0;
        }
    }
    Ok(())
}

pub fn mender_artifact_round_up(length: usize, incr: usize) -> usize {
    length + (incr - length % incr) % incr
}
