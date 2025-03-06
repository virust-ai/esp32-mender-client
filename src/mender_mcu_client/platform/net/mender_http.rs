extern crate alloc;
use crate::custom::mender_config::ROOT_CERT;
use crate::mender_mcu_client::core::mender_client::MENDER_CLIENT_RNG;
use crate::mender_mcu_client::core::mender_utils::{MenderResult, MenderStatus};
use crate::mender_mcu_client::mender_common::MenderCallback;
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use embassy_net::{dns::DnsQueryType, tcp::TcpSocket, IpAddress, Stack};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embedded_io_async::Write;
use embedded_tls::{
    Aes128GcmSha256, TlsConfig, TlsConnection, TlsContext, TlsError, UnsecureProvider,
};

const HTTP_RECV_BUF_LENGTH: usize = 4096;
const HTTP_DEFAULT_PORT: u16 = 80;
const HTTPS_DEFAULT_PORT: u16 = 443;

const USER_AGENT: &str = concat!(
    "mender-mcu-client/",
    env!("CARGO_PKG_VERSION"),
    " (mender-http) embassy-net"
);

static MENDER_HTTP_CONFIG: Mutex<CriticalSectionRawMutex, Option<MenderHttpConfig>> =
    Mutex::new(None);

pub struct SendSyncStack(pub Stack<'static>);

unsafe impl Send for SendSyncStack {}
unsafe impl Sync for SendSyncStack {}

static MENDER_HTTP_STACK: Mutex<CriticalSectionRawMutex, Option<SendSyncStack>> = Mutex::new(None);

// Response data struct to collect response text
#[derive(Default)]
pub struct MenderHttpResponseData {
    pub text: Option<String>,
}

#[derive(Clone)]
pub struct MenderHttpConfig {
    pub host: String,
}

pub struct HttpRequestParams<'a> {
    pub jwt: Option<&'a str>,
    pub path: &'a str,
    pub method: HttpMethod,
    pub payload: Option<&'a str>,
    pub signature: Option<&'a str>,
    pub callback: &'a dyn HttpCallback,
    pub response_data: &'a mut MenderHttpResponseData,
    pub status: &'a mut i32,
    pub params: Option<&'a (dyn MenderCallback + Send + Sync)>,
}

// Initialize function
pub async fn mender_http_init(
    config: &MenderHttpConfig,
    //stack: &'static Stack<WifiDevice<'static, WifiStaDevice>>
    stack: Stack<'static>,
) -> MenderResult<()> {
    let mut conf = MENDER_HTTP_CONFIG.lock().await;
    *conf = Some(config.clone());

    let mut lock = MENDER_HTTP_STACK.lock().await;
    *lock = Some(SendSyncStack(stack));
    Ok((MenderStatus::Ok, ()))
}

async fn try_dns_query(stack: &Stack<'static>, host: &str) -> Result<IpAddress, MenderStatus> {
    const DNS_RETRY_COUNT: u8 = 3;
    const DNS_TIMEOUT_SECS: u64 = 5;

    for attempt in 0..DNS_RETRY_COUNT {
        if attempt > 0 {
            log_info!("Retrying DNS query, attempt: {}", attempt + 1);
            // Add delay between retries
            embassy_time::Timer::after(embassy_time::Duration::from_millis(500)).await;
        }

        match embassy_time::with_timeout(
            embassy_time::Duration::from_secs(DNS_TIMEOUT_SECS),
            stack.dns_query(host, DnsQueryType::A),
        )
        .await
        {
            Ok(Ok(addrs)) => {
                if let Some(&addr) = addrs.first() {
                    log_debug!("DNS query successful, host: {}, addr: {}", host, addr);
                    return Ok(addr);
                }
            }
            Ok(Err(e)) => {
                log_error!("DNS query failed: {}", format_args!("{:?}", e));
            }
            Err(_) => {
                log_error!("DNS query timeout, attempt: {}", attempt + 1);
            }
        }
    }

    log_error!("All DNS query attempts failed, host: {}", host);
    Err(MenderStatus::Network)
}

// Connect function
pub async fn connect_to_host<'a>(
    url: &str,
    rx_buf: &'a mut [u8],
    tx_buf: &'a mut [u8],
    read_record_buffer: &'a mut [u8],
    write_record_buffer: &'a mut [u8],
) -> Result<TlsConnection<'a, TcpSocket<'a>, Aes128GcmSha256>, MenderStatus> {
    // Parse URL to get host and port
    let (host, port) = if let Some(host_str) = url.strip_prefix("http://") {
        (host_str, HTTP_DEFAULT_PORT)
    } else if let Some(host_str) = url.strip_prefix("https://") {
        (host_str, HTTPS_DEFAULT_PORT)
    } else {
        (url, HTTP_DEFAULT_PORT)
    };

    // Remove path portion from host if present
    let host = host.split('/').next().ok_or(MenderStatus::Other)?;

    // Retrieve and clone the stack
    let stack = {
        let lock = MENDER_HTTP_STACK.lock().await;
        lock.as_ref().ok_or(MenderStatus::Other)?.0 // Access the inner Stack with .0
    }; // `lock` is dropped here

    // Check if wifi is connected
    if !stack.is_link_up() {
        log_error!("Network link is down");
        return Err(MenderStatus::Other);
    }

    let addr = try_dns_query(&stack, host).await?;
    //log_info!("DNS lookup successful, addr: {}", addr);

    // Create a new socket using the inner Stack reference
    let mut socket = TcpSocket::new(stack, rx_buf, tx_buf);

    // Set socket timeouts
    socket.set_timeout(Some(embassy_time::Duration::from_secs(5))); // 5 second timeout for operations

    //log_info!("Connecting to host...");
    match embassy_time::with_timeout(
        embassy_time::Duration::from_secs(10), // 10 second connection timeout
        socket.connect((addr, port)),
    )
    .await
    {
        Ok(Ok(_)) => {
            log_info!("Connected to host: {}, port: {}", host, port);
        }
        Ok(Err(e)) => {
            log_error!("Socket connect error: {:?}", e);
            return Err(MenderStatus::Other);
        }
        Err(_) => {
            log_error!("Socket connect timeout");
            return Err(MenderStatus::Other);
        }
    }

    let cert = embedded_tls::Certificate::X509(ROOT_CERT.as_bytes());

    let config = TlsConfig::new().with_cert(cert).with_server_name(host);
    //.with_max_fragment_length(MaxFragmentLength::Bits11);
    //.enable_rsa_signatures();

    let mut lock = MENDER_CLIENT_RNG.lock().await;
    let rng = lock.as_mut().ok_or(MenderStatus::Failed)?;

    //log_info!("Creating TLS context...");
    let context = TlsContext::new(
        &config,
        UnsecureProvider::new::<Aes128GcmSha256>(rng.get_trng()),
    );

    // Create and configure TLS connection
    let mut tls_conn = TlsConnection::new(socket, read_record_buffer, write_record_buffer);

    log_info!("Starting TLS handshake...");
    let start = embassy_time::Instant::now();
    match embassy_time::with_timeout(
        embassy_time::Duration::from_secs(10), // 10 second TLS handshake timeout
        tls_conn.open(context),
    )
    .await
    {
        Ok(Ok(_)) => {
            let duration = start.elapsed();
            log_debug!(
                "TLS handshake succeeded, duration_ms: {}",
                duration.as_millis()
            );
        }
        Ok(Err(e)) => {
            log_error!("TLS handshake failed: {:?}", e);
            return Err(MenderStatus::Network);
        }
        Err(_) => {
            log_error!("TLS handshake timeout");
            return Err(MenderStatus::Network);
        }
    }
    log_info!("TLS connection established, host: {}, port: {}", host, port);

    Ok(tls_conn)
}

pub trait HttpCallback {
    fn call<'a>(
        &'a self,
        event: HttpClientEvent,
        data: Option<&'a [u8]>,
        response_data: Option<&'a mut MenderHttpResponseData>,
        params: Option<&'a (dyn MenderCallback + Send + Sync)>,
    ) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'a>>;
}

// Add this new function to parse chunked encoding
fn parse_chunk_size(data: &[u8]) -> Option<(usize, usize)> {
    // Find the end of the chunk size line (marked by \r\n)
    for i in 0..data.len().saturating_sub(1) {
        if &data[i..i + 2] == b"\r\n" {
            // Convert the hex string to a number
            if let Ok(chunk_header) = core::str::from_utf8(&data[..i]) {
                // Remove any chunk extensions (after semicolon)
                let chunk_size_str = chunk_header.split(';').next()?;
                // Parse the hexadecimal number
                if let Ok(size) = usize::from_str_radix(chunk_size_str.trim(), 16) {
                    return Some((size, i + 2)); // +2 for \r\n
                }
            }
        }
    }
    None
}

// Modify get_content_length to also check for chunked encoding
fn get_transfer_encoding(headers: &[u8]) -> TransferEncoding {
    if let Ok(headers_str) = core::str::from_utf8(headers) {
        for line in headers_str.lines() {
            if line.to_lowercase().starts_with("transfer-encoding:") {
                if let Some(value) = line.split(':').nth(1) {
                    let encoding = value.trim().to_lowercase();
                    if encoding == "chunked" {
                        return TransferEncoding::Chunked;
                    }
                }
            } else if line.to_lowercase().starts_with("content-length:") {
                if let Some(value) = line.split(':').nth(1) {
                    if let Ok(length) = value.trim().parse::<usize>() {
                        return TransferEncoding::ContentLength(length);
                    }
                }
            }
        }
    }
    TransferEncoding::Unknown
}

#[derive(Debug, Clone, Copy)]
enum TransferEncoding {
    Chunked,
    ContentLength(usize),
    Unknown,
}

pub async fn mender_http_perform(params: HttpRequestParams<'_>) -> Result<(), MenderStatus> {
    const MAX_RETRIES: u8 = 3;
    let mut retry_count = 0;

    while retry_count < MAX_RETRIES {
        match try_http_request(
            params.jwt,
            params.path,
            params.method,
            params.payload,
            params.signature,
            params.callback,
            params.response_data,
            params.status,
            params.params,
        )
        .await
        {
            Ok(_) => return Ok(()),
            Err(e) => {
                match e {
                    MenderStatus::Network => {
                        if retry_count < MAX_RETRIES - 1 {
                            log_warn!(
                                "Network error, retrying attempt: {}, error: {:?}",
                                retry_count + 1,
                                e
                            );

                            // Add exponential backoff
                            embassy_time::Timer::after(embassy_time::Duration::from_millis(
                                500 * (2_u64.pow(retry_count as u32)),
                            ))
                            .await;
                            retry_count += 1;
                            continue;
                        }
                        return Err(e);
                    }
                    // For any other error type, return immediately
                    _ => {
                        log_error!("Non-network error {:?} occurred", e);
                        return Err(e);
                    }
                }
            }
        }
    }
    Err(MenderStatus::Other)
}

// Update perform function with better error handling and data management
#[allow(clippy::too_many_arguments)]
async fn try_http_request<'a>(
    jwt: Option<&str>,
    path: &str,
    method: HttpMethod,
    payload: Option<&str>,
    signature: Option<&str>,
    callback: &'a dyn HttpCallback,
    response_data: &mut MenderHttpResponseData,
    status: &mut i32,
    params: Option<&'a (dyn MenderCallback + Send + Sync)>,
) -> Result<(), MenderStatus> {
    //log_info!("try_http_request", "path" => path);
    let config = MENDER_HTTP_CONFIG
        .lock()
        .await
        .as_ref()
        .ok_or(MenderStatus::Other)?
        .clone();

    let url = if !path.starts_with("http://") && !path.starts_with("https://") {
        format!("{}{}", config.host, path)
    } else {
        path.to_string()
    };

    log_debug!("url: {}", url);

    let mut read_record_buffer = [0u8; 16640];
    let mut write_record_buffer = [0u8; 2048];
    let mut rx_buf = [0; 2048];
    let mut tx_buf = [0; 2048];

    let mut retry_count = 0;
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_MS: u64 = 1000;

    let mut bytes_received = 0;
    let mut content_length: Option<usize> = None;
    let mut headers_done = false;
    let mut buffer = [0u8; HTTP_RECV_BUF_LENGTH];

    let mut partial_chunk_size: Option<usize> = None;
    let mut partial_chunk_received: usize = 0;

    // Check if this is a download request (GET method with specific paths)
    let is_download = matches!(method, HttpMethod::Get)
        && (path.contains("download")
            || path.contains("artifacts")
            || path.contains("cloudflarestorage.com")
            || path.contains("mender-artifact-storage"));

    log_debug!("is_download: {}", is_download);

    'retry_loop: while retry_count < MAX_RETRIES {
        log_info!("retry_count: {}", retry_count);
        let mut tls_conn = connect_to_host(
            &url,
            &mut rx_buf,
            &mut tx_buf,
            &mut read_record_buffer,
            &mut write_record_buffer,
        )
        .await?;

        // Build request headers
        let mut headers =
            build_header_request(method, path, jwt, signature, payload, &config, is_download)?;

        // Add Range header only for downloads that are being resumed
        if is_download && bytes_received > 0 {
            headers = headers.trim_end_matches("\r\n").to_string();
            headers.push_str(&format!("Range: bytes={}-\r\n", bytes_received));
            headers.push_str("\r\n");
            log_info!("Resuming download from byte: {}", bytes_received);
        }

        if (tls_conn.write_all(headers.as_bytes()).await).is_err() {
            log_error!("Unable to write request");
            if !is_download {
                return Err(MenderStatus::Network);
            }
            retry_count += 1;
            embassy_time::Timer::after(embassy_time::Duration::from_millis(
                RETRY_DELAY_MS * (2_u64.pow(retry_count)),
            ))
            .await;
            continue 'retry_loop;
        }

        if let Err(e) = tls_conn.flush().await {
            log_error!("Unable to flush headers, error: {:?}", e);
            if !is_download {
                return Err(MenderStatus::Network);
            }
            retry_count += 1;
            embassy_time::Timer::after(embassy_time::Duration::from_millis(
                RETRY_DELAY_MS * (2_u64.pow(retry_count)),
            ))
            .await;
            continue 'retry_loop;
        }

        // Write payload if present (only on first attempt or non-download requests)
        if payload.is_some() && (!is_download || bytes_received == 0) {
            if let Err(e) = tls_conn.write_all(payload.unwrap().as_bytes()).await {
                log_error!("Unable to write payload, error: {:?}", e);
                if !is_download {
                    return Err(MenderStatus::Network);
                }
                retry_count += 1;
                embassy_time::Timer::after(embassy_time::Duration::from_millis(
                    RETRY_DELAY_MS * (2_u64.pow(retry_count)),
                ))
                .await;
                continue 'retry_loop;
            }
            if let Err(e) = tls_conn.flush().await {
                log_error!("Unable to flush payload, error: {:?}", e);
                if !is_download {
                    return Err(MenderStatus::Network);
                }
                retry_count += 1;
                embassy_time::Timer::after(embassy_time::Duration::from_millis(
                    RETRY_DELAY_MS * (2_u64.pow(retry_count)),
                ))
                .await;
                continue 'retry_loop;
            }
        }

        // Connected event (only on first attempt)
        if bytes_received == 0 {
            callback
                .call(
                    HttpClientEvent::Connected,
                    None,
                    Some(response_data),
                    params,
                )
                .await?;
        }

        //let start_time = embassy_time::Instant::now();
        let timeout_duration = embassy_time::Duration::from_secs(15);

        #[allow(unused_labels)]
        'read_loop: loop {
            match embassy_time::with_timeout(timeout_duration, tls_conn.read(&mut buffer)).await {
                Ok(Ok(0)) => {
                    log_info!("Connection closed by server");
                    let _ = tls_conn.close().await;

                    if is_download
                        && content_length.is_some()
                        && bytes_received < content_length.unwrap()
                    {
                        log_warn!("Incomplete download, retrying...");
                        retry_count += 1;
                        embassy_time::Timer::after(embassy_time::Duration::from_millis(
                            RETRY_DELAY_MS * (2_u64.pow(retry_count)),
                        ))
                        .await;
                        continue 'retry_loop;
                    }
                    break 'retry_loop;
                }
                Ok(Ok(n)) => {
                    retry_count = 0; // Reset retry count on successful read

                    if !headers_done {
                        if let Some((headers_end, parsed_status)) = parse_headers(&buffer[..n]) {
                            //log_info!("parse_headers", "headers_end" => headers_end, "parsed_status" => parsed_status);
                            *status = parsed_status;
                            headers_done = true;

                            if parsed_status == 204 {
                                //log_info!("Received 204 No Content");
                                callback
                                    .call(
                                        HttpClientEvent::DataReceived,
                                        Some(&[]),
                                        Some(response_data),
                                        params,
                                    )
                                    .await?;
                                let _ = tls_conn.close().await;
                                break 'retry_loop;
                            }

                            // Process any data after headers in this read
                            let transfer_encoding = get_transfer_encoding(&buffer[..headers_end]);
                            match transfer_encoding {
                                TransferEncoding::Chunked => {
                                    let mut current_pos = headers_end;
                                    while current_pos < n {
                                        if let Some(chunk_size) = partial_chunk_size {
                                            // Continue receiving partial chunk
                                            let remaining = chunk_size - partial_chunk_received;
                                            let available = n - current_pos;
                                            let to_read = remaining.min(available);

                                            log_info!("Continuing partial chunk, remaining: {}, available: {}, to_read: {}", remaining, available, to_read);

                                            callback
                                                .call(
                                                    HttpClientEvent::DataReceived,
                                                    Some(
                                                        &buffer[current_pos..current_pos + to_read],
                                                    ),
                                                    Some(response_data),
                                                    params,
                                                )
                                                .await?;

                                            partial_chunk_received += to_read;
                                            current_pos += to_read;

                                            if partial_chunk_received == chunk_size {
                                                // Full chunk received
                                                partial_chunk_size = None;
                                                partial_chunk_received = 0;
                                                current_pos += 2; // Skip \r\n
                                            } else {
                                                break; // Need more data
                                            }
                                        } else if let Some((chunk_size, header_len)) =
                                            parse_chunk_size(&buffer[current_pos..n])
                                        {
                                            log_info!(
                                                "Chunk info, size: {}, header_len: {}",
                                                chunk_size,
                                                header_len
                                            );
                                            if chunk_size == 0 {
                                                // Last chunk received
                                                log_info!("Last chunk received");
                                                return Ok(());
                                            }
                                            current_pos += header_len;
                                            let available = n - current_pos;

                                            if available >= chunk_size {
                                                // Full chunk available
                                                log_info!(
                                                    "Processing full chunk, size: {}",
                                                    chunk_size
                                                );
                                                callback
                                                    .call(
                                                        HttpClientEvent::DataReceived,
                                                        Some(
                                                            &buffer[current_pos
                                                                ..current_pos + chunk_size],
                                                        ),
                                                        Some(response_data),
                                                        params,
                                                    )
                                                    .await?;
                                                current_pos += chunk_size + 2; // Skip chunk data and \r\n
                                            } else {
                                                // Partial chunk
                                                log_info!("Starting partial chunk, size: {}, available: {}", chunk_size, available);

                                                callback
                                                    .call(
                                                        HttpClientEvent::DataReceived,
                                                        Some(&buffer[current_pos..n]),
                                                        Some(response_data),
                                                        params,
                                                    )
                                                    .await?;
                                                partial_chunk_size = Some(chunk_size);
                                                partial_chunk_received = available;
                                                break;
                                            }
                                        } else {
                                            log_error!("Incomplete chunk header");
                                            break; // Incomplete chunk header
                                        }
                                    }
                                }
                                TransferEncoding::ContentLength(length) => {
                                    log_debug!("Content-Length response, length: {}", length);
                                    content_length = Some(length);
                                    if headers_end < n {
                                        let data_length = n - headers_end;
                                        log_debug!(
                                            "Processing initial data, length: {}",
                                            data_length
                                        );
                                        callback
                                            .call(
                                                HttpClientEvent::DataReceived,
                                                Some(&buffer[headers_end..n]),
                                                Some(response_data),
                                                params,
                                            )
                                            .await?;
                                        bytes_received += data_length;
                                        log_debug!(
                                            "Progress, received: {}, total: {}",
                                            bytes_received,
                                            length
                                        );
                                    }
                                }
                                TransferEncoding::Unknown => {
                                    if headers_end < n {
                                        callback
                                            .call(
                                                HttpClientEvent::DataReceived,
                                                Some(&buffer[headers_end..n]),
                                                Some(response_data),
                                                params,
                                            )
                                            .await?;
                                    }
                                }
                            }
                        }
                    } else if let Some(length) = content_length {
                        // Handle Content-Length response data
                        log_debug!("Processing data chunk, length: {}", n);
                        callback
                            .call(
                                HttpClientEvent::DataReceived,
                                Some(&buffer[..n]),
                                Some(response_data),
                                params,
                            )
                            .await?;
                        bytes_received += n;
                        log_debug!("Progress, received: {}, total: {}", bytes_received, length);

                        if bytes_received >= length {
                            log_debug!("Response complete");
                            let _ = tls_conn.close().await;
                            break 'retry_loop;
                        }
                    } else {
                        log_info!("Processing data chunk in a loop, length: {}", n);
                        // Similar changes for the subsequent reads after headers
                        let mut current_pos = 0;
                        while current_pos < n {
                            if let Some(chunk_size) = partial_chunk_size {
                                // Continue receiving partial chunk
                                let remaining = chunk_size - partial_chunk_received;
                                let available = n - current_pos;
                                let to_read = remaining.min(available);

                                log_info!("Continuing partial chunk, remaining: {}, available: {}, to_read: {}", remaining, available, to_read);

                                callback
                                    .call(
                                        HttpClientEvent::DataReceived,
                                        Some(&buffer[current_pos..current_pos + to_read]),
                                        Some(response_data),
                                        params,
                                    )
                                    .await?;

                                partial_chunk_received += to_read;
                                current_pos += to_read;

                                if partial_chunk_received == chunk_size {
                                    // Full chunk received
                                    partial_chunk_size = None;
                                    partial_chunk_received = 0;
                                    current_pos += 2; // Skip \r\n
                                } else {
                                    break; // Need more data
                                }
                            } else if let Some((chunk_size, header_len)) =
                                parse_chunk_size(&buffer[current_pos..n])
                            {
                                log_info!(
                                    "Processing chunk, size: {}, header_len: {}",
                                    chunk_size,
                                    header_len
                                );
                                if chunk_size == 0 {
                                    let _ = tls_conn.close().await;
                                    // Last chunk received
                                    log_info!("Last chunk received");
                                    break 'retry_loop;
                                }
                                current_pos += header_len;
                                let chunk_end = current_pos + chunk_size;
                                if chunk_end <= n {
                                    log_info!(
                                        "Processing chunk data, size: {}, data: {}",
                                        chunk_size,
                                        core::str::from_utf8(&buffer[current_pos..chunk_end])
                                            .unwrap_or("invalid utf8")
                                    );
                                    callback
                                        .call(
                                            HttpClientEvent::DataReceived,
                                            Some(&buffer[current_pos..chunk_end]),
                                            Some(response_data),
                                            params,
                                        )
                                        .await?;
                                    bytes_received += chunk_size;
                                    current_pos = chunk_end + 2; // Skip the trailing \r\n
                                } else {
                                    // Partial chunk received, need more data
                                    log_info!(
                                        "Partial chunk, available: {}, needed: {}",
                                        n - current_pos,
                                        chunk_size
                                    );
                                    callback
                                        .call(
                                            HttpClientEvent::DataReceived,
                                            Some(&buffer[current_pos..n]),
                                            Some(response_data),
                                            params,
                                        )
                                        .await?;
                                    bytes_received += n - current_pos;
                                    break;
                                }
                            } else {
                                log_error!("Incomplete chunk header");
                                break; // Incomplete chunk header
                            }
                        }
                    }

                    // if let Some(length) = content_length {
                    //     if bytes_received >= length {
                    //         log_info!("Data received complete");
                    //         break;
                    //     }
                    // }
                }
                Ok(Err(e)) => {
                    log_error!("TLS read error: {:?}", e);

                    let _ = tls_conn.close().await;

                    match e {
                        TlsError::ConnectionClosed => {
                            log_info!("Connection closed by server");
                            break 'retry_loop;
                        }
                        _ => {
                            if let Some(length) = content_length {
                                if bytes_received < length {
                                    log_warn!("Incomplete data received, received: {}, total: {}, retrying...",
                                        bytes_received,
                                        length
                                    );
                                    retry_count += 1;
                                    embassy_time::Timer::after(
                                        embassy_time::Duration::from_millis(
                                            RETRY_DELAY_MS * (2_u64.pow(retry_count)),
                                        ),
                                    )
                                    .await;
                                    continue 'retry_loop;
                                } else {
                                    log_info!("Response complete");
                                    break 'retry_loop;
                                }
                            } else {
                                if !is_download {
                                    return Err(MenderStatus::Network);
                                }
                                retry_count += 1;
                                embassy_time::Timer::after(embassy_time::Duration::from_millis(
                                    RETRY_DELAY_MS * (2_u64.pow(retry_count)),
                                ))
                                .await;
                                continue 'retry_loop;
                            }
                        }
                    }
                }
                Err(_) => {
                    log_error!("Response timeout");
                    let _ = tls_conn.close().await;
                    if !is_download {
                        return Err(MenderStatus::Network);
                    }
                    retry_count += 1;
                    embassy_time::Timer::after(embassy_time::Duration::from_millis(
                        RETRY_DELAY_MS * (2_u64.pow(retry_count)),
                    ))
                    .await;
                    continue 'retry_loop;
                }
            }
        } // end read_loop
    }

    log_info!("Disconnected from host");
    callback
        .call(
            HttpClientEvent::Disconnected,
            None,
            Some(response_data),
            params,
        )
        .await?;

    Ok(())
}

fn extract_host(url: &str) -> Result<&str, MenderStatus> {
    // Strip the scheme ("http://" or "https://") and split by '/'
    let url_without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or(MenderStatus::Other)?;

    // Extract the host part before the first '/' (if present)
    let host = url_without_scheme
        .split('/')
        .next()
        .ok_or(MenderStatus::Other)?;

    Ok(host)
}

fn build_header_request(
    method: HttpMethod,
    path: &str,
    jwt: Option<&str>,
    signature: Option<&str>,
    payload: Option<&str>,
    config: &MenderHttpConfig,
    is_download: bool,
) -> Result<String, MenderStatus> {
    //log_info!("build_header_request");

    let host = extract_host(&config.host)?;
    let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
    request.push_str(&format!("Host: {}\r\n", host));
    request.push_str(&format!("User-Agent: {}\r\n", USER_AGENT));

    // Use keep-alive with timeout for downloads, close for other requests
    if is_download {
        request.push_str("Connection: keep-alive\r\n");
        request.push_str("Keep-Alive: timeout=30\r\n"); // 30 second timeout
    } else {
        request.push_str("Connection: close\r\n");
    }

    if let Some(token) = jwt {
        request.push_str(&format!("Authorization: Bearer {}\r\n", token));
    }

    if let Some(sig) = signature {
        request.push_str(&format!("X-MEN-Signature: {}\r\n", sig));
    }

    if payload.is_some() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", payload.unwrap().len()));
    } else {
        request.push_str("Content-Length: 0\r\n");
    }

    request.push_str("\r\n");

    log_debug!("request: {}", request);
    Ok(request)
}

// Helper functions for header parsing
fn parse_headers(data: &[u8]) -> Option<(usize, i32)> {
    // Look for end of headers marked by \r\n\r\n
    let mut headers_end = 0;
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            headers_end = i + 4;
            break;
        }
    }
    if headers_end == 0 {
        return None;
    }

    // Parse status line (e.g., "HTTP/1.1 200 OK")
    let headers = core::str::from_utf8(&data[..headers_end]).ok()?;
    log_debug!("headers: {}, headers_end: {}", headers, headers_end);
    let status_line = headers.lines().next()?;
    let status_code = status_line.split_whitespace().nth(1)?.parse::<i32>().ok()?;

    Some((headers_end, status_code))
}

#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    #[allow(dead_code)]
    Patch,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Patch => write!(f, "PATCH"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum HttpClientEvent {
    Connected,
    DataReceived,
    Disconnected,
    #[allow(dead_code)]
    Error,
}

pub async fn mender_http_exit() {
    let mut conf = MENDER_HTTP_CONFIG.lock().await;
    *conf = None;
}
