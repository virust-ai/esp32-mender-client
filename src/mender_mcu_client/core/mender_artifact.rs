#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use crate::{
    mender_mcu_client::core::mender_utils::{self, MenderResult, MenderStatus},
    mender_mcu_client::mender_common::{MenderCallback, MenderCallbackInfo},
};

use crate::mender_mcu_client::mender_common::{serde_bytes_str, serde_bytes_str_vec};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use heapless::Vec as HVec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
enum MenderArtifactStreamState {
    ParsingHeader, // Currently parsing header
    ParsingData,   // Currently parsing data
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MenderArtifactPayload {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    #[serde(with = "serde_bytes_str")]
    payload_type: String,
    #[serde(with = "serde_bytes_str")]
    checksum: String,
    meta_data: Option<JsonResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonResponse {
    #[serde(with = "serde_bytes_str")]
    error: String,
}

pub struct MenderArtifactContext {
    stream_state: MenderArtifactStreamState,
    input: MenderArtifactInput,
    payloads: MenderArtifactPayloads,
    file: MenderArtifactFile,
}

struct MenderArtifactInput {
    data: Vec<u8>, // Data received chunk by chunk
    length: u32,   // Length of data received
}

struct MenderArtifactPayloads {
    size: u32,                          // Number of payloads
    values: Vec<MenderArtifactPayload>, // Values of payloads
}

struct MenderArtifactFile {
    name: String, // Name of file being parsed
    size: u32,    // Size of file in bytes
    index: u32,   // Current position in file
}

const MENDER_ARTIFACT_STREAM_BLOCK_SIZE: u32 = 512;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionInfo<'a> {
    format: &'a str,
    version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeaderInfo {
    payloads: HVec<PayloadInfo, 1>, // We only expect one payload
    artifact_provides: ArtifactProvides,
    artifact_depends: ArtifactDepends,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PayloadInfo {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    #[serde(with = "serde_bytes_str")]
    payload_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactProvides {
    #[serde(with = "serde_bytes_str")]
    artifact_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactDepends {
    #[serde(with = "serde_bytes_str_vec")]
    device_type: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TypeInfo {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    #[serde(with = "serde_bytes_str")]
    type_name: String,
    artifact_provides: RootfsImageProvides,
    #[serde(with = "serde_bytes_str_vec")]
    clears_artifact_provides: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RootfsImageProvides {
    #[serde(rename = "rootfs-image.checksum")]
    #[serde(alias = "module-image.checksum")]
    #[serde(with = "serde_bytes_str")]
    checksum: String, // For SHA-256 hash

    #[serde(rename = "rootfs-image.version")]
    #[serde(alias = "module-image.version")]
    #[serde(with = "serde_bytes_str")]
    version: String,
}

impl Default for MenderArtifactContext {
    fn default() -> Self {
        Self::new()
    }
}

impl MenderArtifactContext {
    pub fn new() -> Self {
        Self {
            stream_state: MenderArtifactStreamState::ParsingHeader,
            input: MenderArtifactInput {
                data: Vec::new(),
                length: 0,
            },
            payloads: MenderArtifactPayloads {
                size: 0,
                values: Vec::new(),
            },
            file: MenderArtifactFile {
                name: String::new(),
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
    log_info!(
        "mender_artifact_process_data input_length: {}",
        input_length
    );
    // Copy data to the end of the internal buffer
    if let Some(data) = input_data {
        if input_length > 0 {
            ctx.input.data.extend_from_slice(&data[..input_length]);
            ctx.input.length += input_length as u32;
            log_debug!("current input length: {}", ctx.input.length);
        }
    }

    // Parse data
    loop {
        let status = match ctx.stream_state {
            MenderArtifactStreamState::ParsingHeader => {
                //log_info!("parsing header");
                // Parse TAR header
                match mender_artifact_parse_tar_header(ctx)? {
                    (MenderStatus::Done, _) => MenderStatus::Done,
                    (status, _) => status,
                }
            }
            MenderArtifactStreamState::ParsingData => {
                //log_info!("parsing data");
                // Treatment depending on the file name
                let status = match ctx.file.name.as_str() {
                    "version" => {
                        log_info!("parsing data version");
                        match mender_artifact_check_version(ctx)? {
                            (MenderStatus::Done, _) => MenderStatus::Done,
                            (status, _) => status,
                        }
                    }
                    "header.tar/header-info" => {
                        log_info!("parsing data header.tar");
                        match mender_artifact_read_header_info(ctx)? {
                            (MenderStatus::Done, _) => MenderStatus::Done,
                            (status, _) => status,
                        }
                    }
                    name if name.starts_with("header.tar/headers")
                        && name.ends_with("type-info") =>
                    {
                        log_info!("parsing type-info");
                        match mender_artifact_read_type_info(ctx)? {
                            (MenderStatus::Done, _) => MenderStatus::Done,
                            (status, _) => status,
                        }
                    }
                    name if name.starts_with("header.tar/headers")
                        && name.ends_with("meta-data") =>
                    {
                        log_info!("parsing data meta");
                        match mender_artifact_read_meta_data(ctx)? {
                            (MenderStatus::Done, _) => MenderStatus::Done,
                            (status, _) => status,
                        }
                    }
                    name if name.starts_with("data") => {
                        //log_info!("parsing data data");
                        match mender_artifact_read_data(ctx, callback).await? {
                            (MenderStatus::Done, _) => MenderStatus::Done,
                            (status, _) => status,
                        }
                    }
                    name if !name.ends_with(".tar") => {
                        //log_info!("parsing data tar");
                        match mender_artifact_drop_file(ctx)? {
                            (MenderStatus::Done, _) => MenderStatus::Done,
                            (status, _) => status,
                        }
                    }
                    _ => {
                        //log_info!("Nothing to do");
                        MenderStatus::Done
                    }
                };

                if status != MenderStatus::Done {
                    status
                } else {
                    //log_info!("parsing done");
                    // Remove the previous file name using mender_utils_strrstr
                    if let Some(substring) =
                        mender_utils::mender_utils_strrstr(&ctx.file.name, ".tar")
                    {
                        let pos = ctx.file.name.len() - substring.len();
                        let new_len = pos + ".tar".len();
                        if new_len <= ctx.file.name.len() {
                            ctx.file.name.truncate(new_len);
                        }
                    } else {
                        ctx.file.name.clear();
                    }

                    // These operations are outside the if condition, matching the C code
                    ctx.file.size = 0;
                    ctx.file.index = 0;

                    // Update the stream state machine
                    ctx.stream_state = MenderArtifactStreamState::ParsingHeader;
                    MenderStatus::Done
                }
            }
        };

        if status != MenderStatus::Done {
            break;
        }
    }

    Ok((MenderStatus::Ok, ()))
}

impl Drop for MenderArtifactContext {
    fn drop(&mut self) {
        log_info!("Dropping MenderArtifactContext");

        // All memory will be automatically freed:
        // - Vec<u8> in input.data
        // - Vec<MenderArtifactPayload> in payloads.values
        // - String in file.name
        // - JsonResponse in meta_data
    }
}

fn mender_artifact_parse_tar_header(ctx: &mut MenderArtifactContext) -> MenderResult<()> {
    log_info!("mender_artifact_parse_tar_header");
    // Check if enough data are received (at least one block)
    if ctx.input.data.is_empty() || ctx.input.length < MENDER_ARTIFACT_STREAM_BLOCK_SIZE {
        return Ok((MenderStatus::Ok, ()));
    }

    // Cast block to TAR header structure safely
    let tar_header = unsafe { &*(ctx.input.data.as_ptr() as *const TarHeader) };

    // Check if file name is provided, else the end of the current TAR file is reached
    if tar_header.name[0] == b'\0' {
        //log_info!("parsing header 1");
        // Check if enough data are received (at least 2 blocks)
        if ctx.input.length < 2 * MENDER_ARTIFACT_STREAM_BLOCK_SIZE {
            return Ok((MenderStatus::Ok, ()));
        }

        // Remove the TAR file name
        if !ctx.file.name.is_empty() {
            //log_info!("parsing header 2");
            if let Some(substring) = mender_utils::mender_utils_strrstr(&ctx.file.name, ".tar") {
                //log_info!("parsing header 3");
                let pos = ctx.file.name.len() - substring.len();
                ctx.file.name.truncate(pos);

                if mender_utils::mender_utils_strrstr(&ctx.file.name, ".tar").is_some() {
                    //log_info!("parsing header 4");
                    // Keep the .tar and truncate after it
                    let new_len = pos + ".tar".len();
                    if new_len <= ctx.file.name.len() {
                        ctx.file.name.truncate(new_len);
                    }
                } else {
                    //log_info!("parsing header 5");
                    ctx.file.name.clear();
                }
            } else {
                //log_info!("parsing header 6");
                ctx.file.name.clear();
            }
        }

        // Shift data in the buffer
        if mender_artifact_shift_data(ctx, 2 * MENDER_ARTIFACT_STREAM_BLOCK_SIZE).is_err() {
            log_error!("Unable to shift input data");
            return Err(MenderStatus::Failed);
        }

        return Ok((MenderStatus::Done, ())); // MENDER_DONE equivalent
    }

    // Check magic
    if &tar_header.magic[..5] != b"ustar" {
        log_error!("Invalid magic");
        return Err(MenderStatus::Failed);
    }

    // Compute the new file name
    let header_name = core::str::from_utf8(&tar_header.name)
        .map_err(|_| MenderStatus::Failed)?
        .trim_matches('\0');

    let new_name = if !ctx.file.name.is_empty() {
        // Equivalent to snprintf(tmp, str_length, "%s/%s", ctx->file.name, tar_header->name)
        format!("{}/{}", ctx.file.name.as_str(), header_name)
    } else {
        // Equivalent to strdup(tar_header->name)
        header_name.to_string()
    };

    // Update ctx.file.name with the new name
    ctx.file.name = new_name.as_str().into();

    // Retrieve file size (parse octal string)
    let size_str = core::str::from_utf8(&tar_header.size)
        .map_err(|_| MenderStatus::Failed)?
        .trim_matches('\0');

    ctx.file.size = u32::from_str_radix(size_str, 8).map_err(|_| MenderStatus::Failed)?;
    ctx.file.index = 0;

    log_debug!("file name: {}", ctx.file.name.as_str());

    // Shift data in the buffer
    if mender_artifact_shift_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE).is_err() {
        log_error!("Unable to shift input data");
        return Err(MenderStatus::Failed);
    }

    // Update the stream state machine
    ctx.stream_state = MenderArtifactStreamState::ParsingData;

    Ok((MenderStatus::Done, ())) // MENDER_DONE equivalent
}

fn mender_artifact_check_version(ctx: &mut MenderArtifactContext) -> MenderResult<()> {
    // Check if all data have been received
    if ctx.input.data.is_empty()
        || ctx.input.length
            < mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)
    {
        return Ok((MenderStatus::Ok, ()));
    }

    // Parse version file
    let (version_info, _): (VersionInfo, _) =
        serde_json_core::from_slice(&ctx.input.data[..ctx.file.size as usize]).map_err(|_| {
            log_error!("Unable to parse version file");
            MenderStatus::Failed
        })?;

    // Check format
    if version_info.format != MENDER_ARTIFACT_VERSION_FORMAT {
        log_error!("Invalid version format");
        return Err(MenderStatus::Failed);
    }

    // Check version
    if version_info.version != MENDER_ARTIFACT_VERSION_VALUE as i64 {
        log_error!("Invalid version value");
        return Err(MenderStatus::Failed);
    }

    log_info!("Artifact has valid version");

    // Shift data in the buffer
    if let Err(e) = mender_artifact_shift_data(
        ctx,
        mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE),
    ) {
        log_error!("Unable to shift input data");
        return Err(e);
    }

    Ok((MenderStatus::Done, ())) // MenderStatus::Done
}

fn mender_artifact_read_header_info(ctx: &mut MenderArtifactContext) -> MenderResult<()> {
    // Check if all data have been received
    if ctx.input.data.is_empty()
        || ctx.input.length
            < mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)
    {
        return Ok((MenderStatus::Ok, ()));
    }

    let json_str = match core::str::from_utf8(&ctx.input.data[..ctx.file.size as usize]) {
        Ok(s) => {
            log_info!("JSON string: {}, length: {}", s, s.len());
            s
        }
        Err(e) => {
            log_error!(
                "Invalid UTF-8 in header-info, error: {}, size: {}",
                e,
                ctx.file.size
            );
            return Err(MenderStatus::Failed);
        }
    };

    // Parse the JSON structure using serde_json_core
    let (header_info, _): (HeaderInfo, _) = match serde_json_core::from_str(json_str) {
        Ok(result) => {
            log_info!("Successfully parsed header-info");
            result
        }
        Err(e) => {
            log_error!(
                "Unable to parse header-info JSON, error: {}, json_content: {}, size: {}",
                e,
                json_str,
                ctx.file.size
            );
            return Err(MenderStatus::Failed);
        }
    };

    // Set payloads size and initialize new vector
    ctx.payloads.size = 1; // We only handle one payload
    ctx.payloads.values = Vec::new();

    // Add the payload to the vector
    ctx.payloads.values.push(MenderArtifactPayload {
        payload_type: header_info.payloads[0].payload_type.as_str().to_string(),
        checksum: String::new(),
        meta_data: None,
    });

    // Shift data in the buffer
    if mender_artifact_shift_data(
        ctx,
        mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE),
    )
    .is_err()
    {
        log_error!("Unable to shift input data");
        return Err(MenderStatus::Failed);
    }

    Ok((MenderStatus::Done, ())) // MenderStatus::Done
}

fn mender_artifact_read_type_info(ctx: &mut MenderArtifactContext) -> MenderResult<()> {
    // Check if all data have been received
    if ctx.input.data.is_empty()
        || ctx.input.length
            < mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)
    {
        return Ok((MenderStatus::Ok, ()));
    }

    let json_str = match core::str::from_utf8(&ctx.input.data[..ctx.file.size as usize]) {
        Ok(s) => {
            log_debug!("Type-info JSON string: {}, length: {}", s, s.len());
            s
        }
        Err(e) => {
            log_error!(
                "Invalid UTF-8 in type-info, error: {}, size: {}",
                e,
                ctx.file.size
            );
            return Err(MenderStatus::Failed);
        }
    };

    // Try parsing with more detailed error handling
    match serde_json_core::from_str::<TypeInfo>(json_str) {
        Ok((type_info, bytes_read)) => {
            log_debug!("Successfully parsed type-info, bytes read: {}, type: {}, checksum: {}, version: {}", bytes_read, type_info.type_name, type_info.artifact_provides.checksum, type_info.artifact_provides.version);

            // Verify that the type matches the payload type from header-info
            // Extract index from filename (similar to meta-data)
            let index = {
                let name = &ctx.file.name;
                if !name.starts_with("header.tar/headers/") || !name.ends_with("/type-info") {
                    log_error!("Invalid artifact format");
                    return Err(MenderStatus::Failed);
                }

                let start = "header.tar/headers/".len();
                let end = name[start..].find('/').ok_or_else(|| {
                    log_error!("Invalid artifact format");
                    MenderStatus::Failed
                })?;

                let index_str = &name[start..start + end];
                let index = index_str.parse::<u32>().map_err(|_| {
                    log_error!("Invalid artifact format");
                    MenderStatus::Failed
                })?;

                if index >= ctx.payloads.size {
                    log_error!("Invalid artifact format");
                    return Err(MenderStatus::Failed);
                }
                index
            };

            ctx.payloads.values[index as usize].checksum =
                type_info.artifact_provides.checksum.as_str().to_string();
            log_info!(
                "type-info checksum: {}",
                ctx.payloads.values[index as usize].checksum.as_str()
            );

            // Shift data in the buffer
            if mender_artifact_shift_data(
                ctx,
                mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE),
            )
            .is_err()
            {
                log_error!("Unable to shift input data");
                return Err(MenderStatus::Failed);
            }

            Ok((MenderStatus::Done, ()))
        }
        Err(e) => {
            log_error!(
                "JSON parse error details, error: {}, json_content: {}, size: {}",
                e,
                json_str,
                ctx.file.size
            );

            Err(MenderStatus::Failed)
        }
    }
}

fn mender_artifact_read_meta_data(ctx: &mut MenderArtifactContext) -> MenderResult<()> {
    // Retrieve payload index from filename using string operations
    let index = {
        let name = &ctx.file.name;
        if !name.starts_with("header.tar/headers/") || !name.ends_with("/meta-data") {
            log_error!("Invalid artifact format");
            return Err(MenderStatus::Failed);
        }

        let start = "header.tar/headers/".len();
        let end = name[start..].find('/').ok_or_else(|| {
            log_error!("Invalid artifact format");
            MenderStatus::Failed
        })?;

        let index_str = &name[start..start + end];
        let index = index_str.parse::<u32>().map_err(|_| {
            log_error!("Invalid artifact format");
            MenderStatus::Failed
        })?;

        if index >= ctx.payloads.size {
            log_error!("Invalid artifact format");
            return Err(MenderStatus::Failed);
        }
        index
    };

    // Check size of the meta-data
    log_debug!("file size: {}", ctx.file.size);
    if mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE) == 0 {
        log_info!("mender_artifact_read_meta_data: Nothing to do");
        // Nothing to do
        return Ok((MenderStatus::Done, ())); // MenderStatus::Done
    }

    // Check if all data have been received
    if ctx.input.data.is_empty()
        || ctx.input.length
            < mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)
    {
        log_info!("mender_artifact_read_meta_data: Nothing to do");
        return Ok((MenderStatus::Ok, ()));
    }

    // First log the raw JSON string
    let json_str = match core::str::from_utf8(&ctx.input.data[..ctx.file.size as usize]) {
        Ok(s) => {
            log_debug!("Meta-data JSON string: {}, length: {}", s, s.len());
            s
        }
        Err(e) => {
            log_error!(
                "Invalid UTF-8 in meta-data, error: {}, size: {}",
                e,
                ctx.file.size
            );

            return Err(MenderStatus::Failed);
        }
    };

    // Read meta-data
    let (meta_data, bytes_read): (JsonResponse, _) =
        serde_json_core::from_slice(&ctx.input.data[..ctx.file.size as usize]).map_err(|e| {
            log_error!(
                "Unable to parse meta-data, error: {}, json_content: {}",
                e,
                json_str
            );

            MenderStatus::Failed
        })?;

    log_info!(
        "Successfully parsed meta-data, bytes read: {}, meta_data: {}",
        bytes_read,
        meta_data.error
    );

    ctx.payloads.values[index as usize].meta_data = Some(meta_data);

    // Shift data in the buffer
    if let Err(e) = mender_artifact_shift_data(
        ctx,
        mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE),
    ) {
        log_error!("Unable to shift input data");
        return Err(e);
    }

    Ok((MenderStatus::Done, ())) // MenderStatus::Done
}

async fn mender_artifact_read_data(
    ctx: &mut MenderArtifactContext,
    callback: Option<&(dyn MenderCallback + Send + Sync)>,
) -> MenderResult<()> {
    //log_info!("mender_artifact_read_data");
    // Retrieve payload index using string operations
    let index = {
        let name = &ctx.file.name;

        // Extract the number part from "data/XXXX.tar"
        let index = if let Some(num_str) = name
            .strip_prefix("data/")
            .and_then(|s| s.split(".tar").next())
        {
            // Parse the number, expecting format like "0000"
            num_str.parse::<u32>().map_err(|_| {
                log_error!("Invalid artifact format - failed to parse index");
                MenderStatus::Failed
            })?
        } else {
            log_error!("Invalid artifact format - wrong filename pattern");
            return Err(MenderStatus::Failed);
        };

        if index >= ctx.payloads.size {
            log_error!("Invalid artifact format - index out of range");
            return Err(MenderStatus::Failed);
        }
        index
    };

    // Check if a file name is provided
    if ctx.file.name.len() == "data/xxxx.tar".len() {
        log_info!("mender_artifact_read_data: Beginning of the data file");
        if let Some(callback_fn) = callback {
            // Get the meta_data string safely
            let meta_data_str = ctx.payloads.values[index as usize]
                .meta_data
                .as_ref()
                .map(|m| m.error.as_str())
                .unwrap_or("");

            callback_fn
                .call(MenderCallbackInfo {
                    type_str: Some(&ctx.payloads.values[index as usize].payload_type),
                    meta: Some(meta_data_str),
                    file: None,
                    size: 0,
                    data: b"",
                    offset: 0,
                    total: 0,
                    chksum: ctx.payloads.values[index as usize].checksum.as_bytes(),
                })
                .await?;

            return Ok((MenderStatus::Done, ()));
        } else {
            log_error!("Invalid callback");
            return Err(MenderStatus::Failed);
        }
    }

    // Check size of the data
    if mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE) == 0 {
        log_info!("mender_artifact_read_data: Nothing to do");
        // Nothing to do
        return Ok((MenderStatus::Done, ()));
    }

    // Parse data until the end of the file has been reached
    while ctx.file.index < ctx.file.size {
        // Check if enough data are received (at least one block)
        if ctx.input.data.is_empty() || ctx.input.length < MENDER_ARTIFACT_STREAM_BLOCK_SIZE {
            //log_info!("mender_artifact_read_data: Nothing to do");
            return Ok((MenderStatus::Ok, ()));
        }

        // Compute length for this block
        let block_length = (ctx.file.size - ctx.file.index).min(MENDER_ARTIFACT_STREAM_BLOCK_SIZE);

        // Get filename after .tar
        let filename = ctx
            .file
            .name
            .split(".tar")
            .nth(1)
            .and_then(|s| if s.len() > 1 { Some(&s[1..]) } else { None })
            .unwrap_or(""); // Provide default empty string if None

        // Invoke callback
        if let Some(callback_fn) = callback {
            let meta_data_str = ctx.payloads.values[index as usize]
                .meta_data
                .as_ref()
                .map(|m| m.error.as_str())
                .unwrap_or(""); // Default to empty string if no meta_data

            callback_fn
                .call(MenderCallbackInfo {
                    type_str: Some(&ctx.payloads.values[index as usize].payload_type),
                    meta: Some(meta_data_str),
                    file: Some(filename),
                    size: ctx.file.size,
                    data: &ctx.input.data,
                    offset: ctx.file.index,
                    total: block_length,
                    chksum: ctx.payloads.values[index as usize].checksum.as_bytes(),
                })
                .await?;
        } else {
            log_error!("Invalid callback");
            return Err(MenderStatus::Failed);
        }

        // Update index
        ctx.file.index += MENDER_ARTIFACT_STREAM_BLOCK_SIZE;

        // Shift data in the buffer
        if let Err(e) = mender_artifact_shift_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE) {
            log_error!("Unable to shift input data");
            return Err(e);
        }
    }

    Ok((MenderStatus::Done, ())) // MenderStatus::Done
}

fn mender_artifact_drop_file(ctx: &mut MenderArtifactContext) -> MenderResult<()> {
    // Check size of the data
    if mender_artifact_round_up(ctx.file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE) == 0 {
        // Nothing to do
        return Ok((MenderStatus::Done, ())); // MenderStatus::Done
    }

    // Parse data until the end of the file has been reached
    while ctx.file.index < ctx.file.size {
        // Check if enough data are received (at least one block)
        if ctx.input.data.is_empty() || ctx.input.length < MENDER_ARTIFACT_STREAM_BLOCK_SIZE {
            return Ok((MenderStatus::Ok, ()));
        }

        // Update index
        ctx.file.index += MENDER_ARTIFACT_STREAM_BLOCK_SIZE;

        // Shift data in the buffer
        if let Err(e) = mender_artifact_shift_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE) {
            log_error!("Unable to shift input data");
            return Err(e);
        }
    }

    Ok((MenderStatus::Done, ())) // MenderStatus::Done
}

fn mender_artifact_shift_data(ctx: &mut MenderArtifactContext, length: u32) -> MenderResult<()> {
    if length > 0 {
        if ctx.input.length > length {
            // Shift remaining data to front of vector
            ctx.input.data.copy_within(length as usize.., 0);
            // Truncate vector to new length
            ctx.input
                .data
                .truncate((ctx.input.length - length) as usize);
            ctx.input.length -= length;
        } else {
            // Clear all data
            ctx.input.data.clear();
            ctx.input.length = 0;
        }
    }
    log_debug!("current input length now: {}", ctx.input.length);
    Ok((MenderStatus::Ok, ()))
}

fn mender_artifact_round_up(length: u32, incr: u32) -> u32 {
    length + (incr - length % incr) % incr
}
