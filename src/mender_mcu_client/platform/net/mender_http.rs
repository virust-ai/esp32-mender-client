extern crate alloc;

use crate::custom::mender_common::MenderCallback;
use crate::mender_mcu_client::core::mender_client::MENDER_CLIENT_RNG;
use crate::mender_mcu_client::core::mender_utils::{MenderError, MenderResult};
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_net::{dns::DnsQueryType, tcp::TcpSocket, IpAddress, Stack};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embedded_io_async::Write;
use embedded_tls::{Aes128GcmSha256, TlsConfig, TlsConnection, TlsContext, UnsecureProvider};
use heapless::FnvIndexMap;

const HTTP_RECV_BUF_LENGTH: usize = 2048;
const HTTP_DEFAULT_PORT: u16 = 80;
const HTTPS_DEFAULT_PORT: u16 = 443;

const USER_AGENT: &str = concat!(
    "mender-mcu-client/",
    env!("CARGO_PKG_VERSION"),
    " (mender-http) embassy-net"
);

static MENDER_HTTP_CONFIG: Mutex<CriticalSectionRawMutex, Option<MenderHttpConfig>> =
    Mutex::new(None);
//static MENDER_HTTP_STACK: Mutex<CriticalSectionRawMutex, Option<Stack<WifiDevice<'static, WifiStaDevice>>>> = Mutex::new(None);
//pub struct SendSyncStack(pub &'static Stack<WifiDevice<'static, WifiStaDevice>>);
pub struct SendSyncStack(pub Stack<'static>);

unsafe impl Send for SendSyncStack {}
unsafe impl Sync for SendSyncStack {}

static MENDER_HTTP_STACK: Mutex<CriticalSectionRawMutex, Option<SendSyncStack>> = Mutex::new(None);

const RX_BUFFER_SIZE: usize = 4096;
const TX_BUFFER_SIZE: usize = 4096;
static mut RX_BUFFER: [u8; RX_BUFFER_SIZE] = [0; RX_BUFFER_SIZE];
static mut TX_BUFFER: [u8; TX_BUFFER_SIZE] = [0; TX_BUFFER_SIZE];

// Store connection info instead of the actual connection
struct CachedConnInfo {
    addr: IpAddress,
    is_alive: AtomicBool,
}

// Update the cache to store connection info
static DNS_PORT_CACHE: Mutex<CriticalSectionRawMutex, FnvIndexMap<String, CachedConnInfo, 2>> =
    Mutex::new(FnvIndexMap::new());

// Update functions to work with connection info
async fn cache_conn_info(host: String, addr: IpAddress) {
    let mut cache = DNS_PORT_CACHE.lock().await;
    let _ = cache.insert(
        host,
        CachedConnInfo {
            addr,
            is_alive: AtomicBool::new(true),
        },
    );
}

async fn get_cached_conn_info(host: &str) -> Option<IpAddress> {
    let cache = DNS_PORT_CACHE.lock().await;
    cache.get(host).and_then(|conn| {
        if conn.is_alive.load(Ordering::Relaxed) {
            Some(conn.addr)
        } else {
            None
        }
    })
}

// Response data struct to collect response text
#[derive(Default)]
pub struct MenderHttpResponseData {
    pub text: Option<String>,
}

#[derive(Clone)]
pub struct MenderHttpConfig {
    pub host: String,
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
    Ok(())
}

fn get_buffers() -> (&'static mut [u8], &'static mut [u8]) {
    unsafe {
        (
            &mut *core::ptr::addr_of_mut!(RX_BUFFER),
            &mut *core::ptr::addr_of_mut!(TX_BUFFER),
        )
    }
}

// Connect function
pub async fn connect_to_host<'a>(
    url: &str,
    read_record_buffer: &'a mut [u8],
    write_record_buffer: &'a mut [u8],
) -> Result<TlsConnection<'a, TcpSocket<'a>, Aes128GcmSha256>, MenderError> {
    // Parse URL to get host and port
    let (host, port) = if let Some(host_str) = url.strip_prefix("http://") {
        (host_str, HTTP_DEFAULT_PORT)
    } else if let Some(host_str) = url.strip_prefix("https://") {
        (host_str, HTTPS_DEFAULT_PORT)
    } else {
        (url, HTTP_DEFAULT_PORT)
    };

    // log_info!("host", "host" => host);
    // log_info!("port", "port" => port);

    // Remove path portion from host if present
    let host = host.split('/').next().ok_or(MenderError::Other)?;

    let (rx_buf, tx_buf) = get_buffers();

    // Retrieve and clone the stack
    let stack = {
        let lock = MENDER_HTTP_STACK.lock().await;
        lock.as_ref().ok_or(MenderError::Other)?.0 // Access the inner Stack with .0
    }; // `lock` is dropped here

    // Check if wifi is connected
    if !stack.is_link_up() {
        log_error!("Network link is down");
        return Err(MenderError::Other);
    }

    let addr = if let Some(cached_addr) = get_cached_conn_info(host).await {
        log_info!("Using cached connection info", "host" => host);
        cached_addr
    } else {
        // DNS lookup with timeout
        let resolved_addr = embassy_time::with_timeout(
            embassy_time::Duration::from_secs(15), // 15 second timeout
            stack.dns_query(host, DnsQueryType::A),
        )
        .await
        .map_err(|_| {
            log_error!("DNS query timeout");
            MenderError::Other
        })?
        .map_err(|_| MenderError::Other)?
        .first()
        .ok_or(MenderError::Other)?
        .clone();

        // Cache the new connection info
        cache_conn_info(host.to_string(), resolved_addr).await;

        resolved_addr
    };

    log_info!("DNS lookup successful", "addr" => addr);

    // Create a new socket using the inner Stack reference
    let mut socket = TcpSocket::new(stack, rx_buf, tx_buf);
    socket
        .connect((addr, port))
        .await
        .map_err(|_| MenderError::Other)?;

    log_info!("Connected to host", "host" => host, "port" => port);

    //let priv_key = PRIVATE_KEY.lock().await.clone().unwrap_or_default();

    let config = TlsConfig::new()
        //.with_cert(cert)
        //.with_priv_key(&priv_key)
        .with_server_name(host)
        //.with_max_fragment_length(MaxFragmentLength::Bits9);
        .enable_rsa_signatures();

    let mut lock = MENDER_CLIENT_RNG.lock().await;
    let rng = lock.as_mut().ok_or(MenderError::Failed)?;

    log_info!("Creating TLS context...");
    let context = TlsContext::new(
        &config,
        UnsecureProvider::new::<Aes128GcmSha256>(rng.get_trng()),
    );

    // Create and configure TLS connection
    let mut tls_conn = TlsConnection::new(socket, read_record_buffer, write_record_buffer);

    log_info!("Starting TLS handshake...");
    let start = embassy_time::Instant::now();
    match tls_conn.open(context).await {
        Ok(_) => {
            let duration = start.elapsed();
            log_info!("TLS handshake succeeded", "duration_s" => duration.as_secs());
        }
        Err(e) => {
            log_error!("TLS handshake failed", "error" => e);
            return Err(MenderError::Other);
        }
    }
    log_info!("TLS connection established", "host" => host, "port" => port);

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

// Update perform function with better error handling and data management
pub async fn mender_http_perform<'a>(
    jwt: Option<&str>,
    path: &str,
    method: HttpMethod,
    payload: Option<&str>,
    signature: Option<&str>,
    callback: &'a dyn HttpCallback,
    response_data: &mut MenderHttpResponseData,
    status: &mut i32,
    params: Option<&'a (dyn MenderCallback + Send + Sync)>,
) -> Result<(), MenderError> {
    log_info!("mender_http_perform", "path" => path);
    let config = MENDER_HTTP_CONFIG
        .lock()
        .await
        .as_ref()
        .ok_or(MenderError::Other)?
        .clone();

    let url = if !path.starts_with("http://") && !path.starts_with("https://") {
        format!("{}{}", config.host, path)
    } else {
        path.to_string()
    };

    log_info!("url", "url" => url);

    let mut read_record_buffer = [0u8; 16384];
    let mut write_record_buffer = [0u8; 16384];

    // Connect to host and get socket
    let mut tls_conn =
        connect_to_host(&url, &mut read_record_buffer, &mut write_record_buffer).await?;
    //let mut tls_conn = get_or_create_tls_connection(&url).await?;

    // Send request with headers
    let headers = build_header_request(method, path, jwt, signature, payload, &config)?;

    // Construct headers
    // let headers = format!(
    //     "POST /api/devices/v1/authentication/auth_requests HTTP/1.1\r\n\
    //     Host: mender.bluleap.ai\r\n\
    //     User-Agent: mender-mcu-client/0.1.0 (mender-http) embassy-net\r\n\
    //     X-MEN-Signature: {}\r\n\
    //     Content-Type: application/json\r\n\
    //     Content-Length: {}\r\n\r\n",
    //     signature.unwrap(),
    //     content_length
    // );

    //log::info!("headers {:?}", headers);

    if tls_conn.write_all(headers.as_bytes()).await.is_err() {
        log_error!("Unable to write request");
        callback
            .call(HttpClientEvent::Error, None, Some(response_data), params)
            .await?;
        return Err(MenderError::Other);
    }

    if let Some(p) = payload {
        if tls_conn.write_all(p.as_bytes()).await.is_err() {
            log_error!("Unable to write request");
            callback
                .call(HttpClientEvent::Error, None, Some(response_data), params)
                .await?;
            return Err(MenderError::Other);
        }
    }

    //tls_conn.write_all(b"ping").await.expect("error writing data");
    tls_conn.flush().await.expect("error flushing data");

    // Connected event
    log_info!("Connected to host");
    callback
        .call(
            HttpClientEvent::Connected,
            None,
            Some(response_data),
            params,
        )
        .await?;

    log_info!("Reading response");
    // Read response with proper error handling
    let mut buffer = vec![0u8; HTTP_RECV_BUF_LENGTH];
    let mut headers_done = false;
    let mut content_length: Option<usize> = None;
    let mut bytes_received = 0;

    loop {
        match tls_conn.read(&mut buffer).await {
            Ok(0) => {
                log_info!("Connection closed");
                break; // Connection closed
            }
            Ok(n) => {
                if !headers_done {
                    if let Some((headers_end, parsed_status)) = parse_headers(&buffer[..n]) {
                        *status = parsed_status;
                        headers_done = true;

                        if parsed_status == 204 {
                            log_info!("Received 204 No Content");
                            callback
                                .call(
                                    HttpClientEvent::DataReceived,
                                    Some(&[]),
                                    Some(response_data),
                                    params,
                                )
                                .await?;
                            break; // Exit loop as no content is expected
                        }

                        content_length = get_content_length(&buffer[..headers_end]);

                        if headers_end < n {
                            //log_info!("Data received at headers_end");
                            callback
                                .call(
                                    HttpClientEvent::DataReceived,
                                    Some(&buffer[headers_end..n]),
                                    Some(response_data),
                                    params,
                                )
                                .await?;
                            bytes_received += n - headers_end;
                        }
                    }
                } else {
                    //log_info!("Data received more");
                    callback
                        .call(
                            HttpClientEvent::DataReceived,
                            Some(&buffer[..n]),
                            Some(response_data),
                            params,
                        )
                        .await?;
                    bytes_received += n;
                }

                if let Some(length) = content_length {
                    if bytes_received >= length {
                        log_info!("Data received complete");
                        break;
                    }
                }
            }
            Err(_) => {
                log_error!("Error reading response");
                callback
                    .call(HttpClientEvent::Error, None, Some(response_data), params)
                    .await?;
                return Err(MenderError::Other);
            }
        }
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

fn extract_host(url: &str) -> Result<&str, MenderError> {
    // Strip the scheme ("http://" or "https://") and split by '/'
    let url_without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or(MenderError::Other)?;

    // Extract the host part before the first '/' (if present)
    let host = url_without_scheme
        .split('/')
        .next()
        .ok_or(MenderError::Other)?;

    Ok(host)
}

fn build_header_request(
    method: HttpMethod,
    path: &str,
    jwt: Option<&str>,
    signature: Option<&str>,
    payload: Option<&str>,
    config: &MenderHttpConfig,
) -> Result<String, MenderError> {
    log_info!("build_header_request");
    let host = extract_host(&config.host)?;
    let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
    request.push_str(&format!("Host: {}\r\n", host));
    request.push_str(&format!("User-Agent: {}\r\n", USER_AGENT));

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
        request.push_str(&"Content-Length: 0\r\n".to_string());
    }

    request.push_str("\r\n");

    //log_info!("request", "request" => request);
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
    let status_line = headers.lines().next()?;
    let status_code = status_line.split_whitespace().nth(1)?.parse::<i32>().ok()?;

    Some((headers_end, status_code))
}

fn get_content_length(headers: &[u8]) -> Option<usize> {
    let headers_str = core::str::from_utf8(headers).ok()?;
    for line in headers_str.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            return line.split(':').nth(1)?.trim().parse::<usize>().ok();
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
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
    Error,
}

pub async fn mender_http_exit() {
    let mut conf = MENDER_HTTP_CONFIG.lock().await;
    *conf = None;
}
