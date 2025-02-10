extern crate alloc;

use crate::custom::mender_common::MenderCallback;
use crate::mender_mcu_client::core::mender_client::MENDER_CLIENT_RNG;
use crate::mender_mcu_client::core::mender_utils::{MenderResult, MenderStatus};
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_net::{dns::DnsQueryType, tcp::TcpSocket, IpAddress, Stack};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embedded_io_async::Write;
use embedded_tls::{
    Aes128GcmSha256, TlsConfig, TlsConnection, TlsContext, TlsError, UnsecureProvider,
};
use heapless::FnvIndexMap;

const HTTP_RECV_BUF_LENGTH: usize = 1024 + 512;
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

static BLUE_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIB0jCCAXmgAwIBAgIUBFs9wGFvoR3FEF9hK5b1iOrZsL0wCgYIKoZIzj0EAwIw\nGzEZMBcGA1UEAwwQZG9ja2VyLm1lbmRlci5pbzAeFw0yMTA2MDExMzExMTNaFw0z\nMTA1MzAxMzExMTNaMBsxGTAXBgNVBAMMEGRvY2tlci5tZW5kZXIuaW8wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAQPyND/aGLxFoMl9PVMQ0gBG74VXK4hVgOWOznX\nVrzoBfETf6wXEyV7Dq217ZxtV7gsafyZ6lWtLx33qRfQd7Exo4GaMIGXMB0GA1Ud\nDgQWBBSjTHcK2xcQFJLrjnAv+0Sl6pLD8zAfBgNVHSMEGDAWgBSjTHcK2xcQFJLr\njnAv+0Sl6pLD8zAPBgNVHRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMB\nMC8GA1UdEQQoMCaCEGRvY2tlci5tZW5kZXIuaW+CEiouZG9ja2VyLm1lbmRlci5p\nbzAKBggqhkjOPQQDAgNHADBEAiAvmTdg3z7GkrnNM+N5ujl4xIm6bdnVhhLXkJdn\nTyWKrwIgN2asFU4swaMUobs6uXMBt5zftfLKwuQIYbBEwBemWFg=\n-----END CERTIFICATE-----";

//static ROOT_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIB0jCCAXmgAwIBAgIUPD+GXVJ83jPLZYEc7gevRKHsdHAwCgYIKoZIzj0EAwIw\nGzEZMBcGA1UEAwwQaG9zdGVkLm1lbmRlci5pbzAeFw0yNTAxMTMwODIwNDRaFw0z\nNTAxMTEwODIwNDRaMBsxGTAXBgNVBAMMEGhvc3RlZC5tZW5kZXIuaW8wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAS+DiZUIcwt+XGkmff5qC8BNTMOKW96vO3bRms4\nYwq5qC0en1QSoQAybQGNDtLErUhGbgDI2Q5WS4Ph712R/WDJo4GaMIGXMB0GA1Ud\nDgQWBBS5zsvs8zEZr9NvvTRoIGCEqtb1HTAfBgNVHSMEGDAWgBS5zsvs8zEZr9Nv\nvTRoIGCEqtb1HTAPBgNVHRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMB\nMC8GA1UdEQQoMCaCEGhvc3RlZC5tZW5kZXIuaW+CEiouaG9zdGVkLm1lbmRlci5p\nbzAKBggqhkjOPQQDAgNHADBEAiAaOtgatdm0dgJS4XcR/ItLlKp5RS1IWpxMT27w\nIPsiGAIgDxodYLHCopT9AgNBOK3vcYlK4KrjJDntwXWFb1JQKYY=\n-----END CERTIFICATE-----";
static ROOT_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIEdTCCA12gAwIBAgIJAKcOSkw0grd/MA0GCSqGSIb3DQEBCwUAMGgxCzAJBgNV\nBAYTAlVTMSUwIwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTIw\nMAYDVQQLEylTdGFyZmllbGQgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0\neTAeFw0wOTA5MDIwMDAwMDBaFw0zNDA2MjgxNzM5MTZaMIGYMQswCQYDVQQGEwJV\nUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTElMCMGA1UE\nChMcU3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjE7MDkGA1UEAxMyU3RhcmZp\nZWxkIFNlcnZpY2VzIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwggEi\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVDDrEKvlO4vW+GZdfjohTsR8/\ny8+fIBNtKTrID30892t2OGPZNmCom15cAICyL1l/9of5JUOG52kbUpqQ4XHj2C0N\nTm/2yEnZtvMaVq4rtnQU68/7JuMauh2WLmo7WJSJR1b/JaCTcFOD2oR0FMNnngRo\nOt+OQFodSk7PQ5E751bWAHDLUu57fa4657wx+UX2wmDPE1kCK4DMNEffud6QZW0C\nzyyRpqbn3oUYSXxmTqM6bam17jQuug0DuDPfR+uxa40l2ZvOgdFFRjKWcIfeAg5J\nQ4W2bHO7ZOphQazJ1FTfhy/HIrImzJ9ZVGif/L4qL8RVHHVAYBeFAlU5i38FAgMB\nAAGjgfAwge0wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0O\nBBYEFJxfAN+qAdcwKziIorhtSpzyEZGDMB8GA1UdIwQYMBaAFL9ft9HO3R+G9FtV\nrNzXEMIOqYjnME8GCCsGAQUFBwEBBEMwQTAcBggrBgEFBQcwAYYQaHR0cDovL28u\nc3MyLnVzLzAhBggrBgEFBQcwAoYVaHR0cDovL3guc3MyLnVzL3guY2VyMCYGA1Ud\nHwQfMB0wG6AZoBeGFWh0dHA6Ly9zLnNzMi51cy9yLmNybDARBgNVHSAECjAIMAYG\nBFUdIAAwDQYJKoZIhvcNAQELBQADggEBACMd44pXyn3pF3lM8R5V/cxTbj5HD9/G\nVfKyBDbtgB9TxF00KGu+x1X8Z+rLP3+QsjPNG1gQggL4+C/1E2DUBc7xgQjB3ad1\nl08YuW3e95ORCLp+QCztweq7dp4zBncdDQh/U90bZKuCJ/Fp1U1ervShw3WnWEQt\n8jxwmKy6abaVd38PMV4s/KCHOkdp8Hlf9BRUpJVeEXgSYCfOn8J3/yNTd126/+pZ\n59vPr5KW7ySaNRB6nJHGDn2Z9j8Z3/VyVOEVqQdZe4O/Ui5GjLIAZHYcSNPYeehu\nVsyuLAOQ1xk4meTKCRlb/weWsKh/NEnfVqn3sF/tM+2MR7cwA130A4w=\n-----END CERTIFICATE-----";

static CLOUDFLARE_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIICeDCCAh6gAwIBAgIUdGybb97s1RnCo5wAqwmD2GCHHIMwCgYIKoZIzj0EAwIw\nRDFCMEAGA1UEAww5YzI3MTk2NGQ0MTc0OWZlYjEwZGE3NjI4MTZjOTUyZWUucjIu\nY2xvdWRmbGFyZXN0b3JhZ2UuY29tMB4XDTI1MDExNzA4MzczNloXDTM1MDExNTA4\nMzczNlowRDFCMEAGA1UEAww5YzI3MTk2NGQ0MTc0OWZlYjEwZGE3NjI4MTZjOTUy\nZWUucjIuY2xvdWRmbGFyZXN0b3JhZ2UuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0D\nAQcDQgAEUFtDg9i9xk78cLEd1xHgoswretxau5hP1bQzAfj7D/AG/650xUJ9n9Qa\naktj851Je6fnG1CBfTbUPOP2Gp08jqOB7TCB6jAdBgNVHQ4EFgQUJQHTo0teO/K8\nc1iZoP1L6Wm7R8gwHwYDVR0jBBgwFoAUJQHTo0teO/K8c1iZoP1L6Wm7R8gwDwYD\nVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggrBgEFBQcDATCBgQYDVR0RBHoweII5\nYzI3MTk2NGQ0MTc0OWZlYjEwZGE3NjI4MTZjOTUyZWUucjIuY2xvdWRmbGFyZXN0\nb3JhZ2UuY29tgjsqLmMyNzE5NjRkNDE3NDlmZWIxMGRhNzYyODE2Yzk1MmVlLnIy\nLmNsb3VkZmxhcmVzdG9yYWdlLmNvbTAKBggqhkjOPQQDAgNIADBFAiEAq9mHtH1w\nrc+1jq3F0TwuiYQH8XcgwRJa8GuLWvw4XP0CIEaIaZ4vXxbrvYH4NqUq4BAFlnce\nJO5o1YPe3GlJvdwI\n-----END CERTIFICATE-----";

static ION_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIB8zCCAZmgAwIBAgIUPs7cEUjaCnOQz3eV5nljyj3jskowCgYIKoZIzj0EAwIw\nIzEhMB8GA1UEAwwYbWVuZGVyLXMuaW9ubW9iaWxpdHkuY29tMB4XDTIzMTAwOTEw\nMzYzN1oXDTMzMTAwNjEwMzYzN1owIzEhMB8GA1UEAwwYbWVuZGVyLXMuaW9ubW9i\naWxpdHkuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIuRIXhcEijAbfGWY\niOcmLyNgghyX15U2U0oxfKu4DsBSl1I6z/2byfICbaklMZctHnPwadEcKd4D+4D/\nnWLBv6OBqjCBpzAdBgNVHQ4EFgQUlupnfE/paWI4xIQ3O21bfdms4fYwHwYDVR0j\nBBgwFoAUlupnfE/paWI4xIQ3O21bfdms4fYwDwYDVR0TAQH/BAUwAwEB/zATBgNV\nHSUEDDAKBggrBgEFBQcDATA/BgNVHREEODA2ghhtZW5kZXItcy5pb25tb2JpbGl0\neS5jb22CGioubWVuZGVyLXMuaW9ubW9iaWxpdHkuY29tMAoGCCqGSM49BAMCA0gA\nMEUCIA/pNz8YCWCXBpdjXmGWfsAMK6y3wAEqLz6jXjBlZTZuAiEA/7/2MeuDJuBG\nOtuZUxkEyhRtZ25shuwU0u92qLc/QYE=\n-----END CERTIFICATE-----";

async fn try_dns_query(stack: &Stack<'static>, host: &str) -> Result<IpAddress, MenderStatus> {
    const DNS_RETRY_COUNT: u8 = 3;
    const DNS_TIMEOUT_SECS: u64 = 5;

    for attempt in 0..DNS_RETRY_COUNT {
        if attempt > 0 {
            log_info!("Retrying DNS query", "attempt" => attempt + 1);
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
                    log_info!("DNS query successful",
                        "host" => host,
                        "addr" => addr,
                        "attempt" => attempt + 1
                    );
                    return Ok(addr);
                }
            }
            Ok(Err(e)) => {
                log_error!("DNS query failed",
                    "error" => format_args!("{:?}", e),
                    "attempt" => attempt + 1
                );
            }
            Err(_) => {
                log_error!("DNS query timeout",
                    "attempt" => attempt + 1
                );
            }
        }
    }

    log_error!("All DNS query attempts failed", "host" => host);
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

    // log_info!("host", "host" => host);
    // log_info!("port", "port" => port);

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

    let addr = if let Some(cached_addr) = get_cached_conn_info(host).await {
        log_info!("Using cached connection info", "host" => host);
        cached_addr
    } else {
        log_info!("Starting DNS query for host", "host" => host);
        let resolved_addr = try_dns_query(&stack, host).await?;
        cache_conn_info(host.to_string(), resolved_addr).await;
        resolved_addr
    };

    log_info!("DNS lookup successful", "addr" => addr);

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
            log_info!("Connected to host", "host" => host, "port" => port);
        }
        Ok(Err(e)) => {
            log_error!("Socket connect error", "error" => e);
            return Err(MenderStatus::Other);
        }
        Err(_) => {
            log_error!("Socket connect timeout");
            return Err(MenderStatus::Other);
        }
    }

    let cert = if host.contains("cloudflarestorage.com") {
        embedded_tls::Certificate::X509(CLOUDFLARE_CERT.as_bytes())
    } else if host.contains("bluleap.ai") {
        embedded_tls::Certificate::X509(BLUE_CERT.as_bytes())
    } else if host.contains("ionmobility.com") {
        embedded_tls::Certificate::X509(ION_CERT.as_bytes())
    } else {
        embedded_tls::Certificate::X509(ROOT_CERT.as_bytes())
    };

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
            log_info!("TLS handshake succeeded", "duration_ms" => duration.as_millis());
        }
        Ok(Err(e)) => {
            log_error!("TLS handshake failed", "error" => e);
            return Err(MenderStatus::Network);
        }
        Err(_) => {
            log_error!("TLS handshake timeout");
            return Err(MenderStatus::Network);
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
                            log_warn!("Network error, retrying",
                                "attempt" => retry_count + 1,
                                "error" => e,
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
                        log_error!("Non-network error occurred", "error" => e);
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

    log_info!("url", "url" => url);

    let mut read_record_buffer = [0u8; 16640];
    let mut write_record_buffer = [0u8; 4096];
    let mut rx_buf = [0; 4096];
    let mut tx_buf = [0; 4096];

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

    log_info!("is_download", "is_download" => is_download);

    'retry_loop: while retry_count < MAX_RETRIES {
        log_info!("retry_count", "retry_count" => retry_count);
        let mut tls_conn = connect_to_host(
            &url,
            &mut rx_buf,
            &mut tx_buf,
            &mut read_record_buffer,
            &mut write_record_buffer,
        )
        .await?;

        // Build request headers
        let mut headers = build_header_request(method, path, jwt, signature, payload, &config)?;

        // Add Range header only for downloads that are being resumed
        if is_download && bytes_received > 0 {
            headers = headers.trim_end_matches("\r\n").to_string();
            headers.push_str(&format!("Range: bytes={}-\r\n\r\n", bytes_received));
            log_info!("Resuming download from byte", "bytes_received" => bytes_received);
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
            log_error!("Unable to flush headers", "error" => e);
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
                log_error!("Unable to write payload", "error" => e);
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
                log_error!("Unable to flush payload", "error" => e);
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
            // log_info!("Attempting to read from TLS connection",
            //     "elapsed_ms" => start_time.elapsed().as_millis(),
            //     "headers_done" => headers_done,
            //     "bytes_received" => bytes_received,
            //     "content_length" => content_length
            // );

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

                                            log_info!("Continuing partial chunk",
                                                "remaining" => remaining,
                                                "available" => available,
                                                "to_read" => to_read
                                            );

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
                                            log_info!("Chunk info", "size" => chunk_size, "header_len" => header_len);
                                            if chunk_size == 0 {
                                                // Last chunk received
                                                log_info!("Last chunk received");
                                                return Ok(());
                                            }
                                            current_pos += header_len;
                                            let available = n - current_pos;

                                            if available >= chunk_size {
                                                // Full chunk available
                                                log_info!("Processing full chunk", "size" => chunk_size);
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
                                                log_info!("Starting partial chunk",
                                                    "size" => chunk_size,
                                                    "available" => available
                                                );
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
                                            break; // Incomplete chunk header
                                        }
                                    }
                                }
                                TransferEncoding::ContentLength(length) => {
                                    log_info!("Content-Length response", "length" => length);
                                    content_length = Some(length);
                                    if headers_end < n {
                                        let data_length = n - headers_end;
                                        log_info!("Processing initial data", "length" => data_length);
                                        callback
                                            .call(
                                                HttpClientEvent::DataReceived,
                                                Some(&buffer[headers_end..n]),
                                                Some(response_data),
                                                params,
                                            )
                                            .await?;
                                        bytes_received += data_length;
                                        log_info!("Progress", "received" => bytes_received, "total" => length);
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
                        log_info!("Processing data chunk", "length" => n);
                        callback
                            .call(
                                HttpClientEvent::DataReceived,
                                Some(&buffer[..n]),
                                Some(response_data),
                                params,
                            )
                            .await?;
                        bytes_received += n;
                        log_info!("Progress", "received" => bytes_received, "total" => length);

                        if bytes_received >= length {
                            log_info!("Response complete");
                            let _ = tls_conn.close().await;
                            break 'retry_loop;
                        }
                    } else {
                        // Similar changes for the subsequent reads after headers
                        let mut current_pos = 0;
                        while current_pos < n {
                            if let Some(chunk_size) = partial_chunk_size {
                                // Continue receiving partial chunk
                                let remaining = chunk_size - partial_chunk_received;
                                let available = n - current_pos;
                                let to_read = remaining.min(available);

                                log_info!("Continuing partial chunk",
                                    "remaining" => remaining,
                                    "available" => available,
                                    "to_read" => to_read
                                );

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
                                log_info!("Processing chunk", "size" => chunk_size, "header_len" => header_len);
                                if chunk_size == 0 {
                                    let _ = tls_conn.close().await;
                                    // Last chunk received
                                    log_info!("Last chunk received");
                                    break 'retry_loop;
                                }
                                current_pos += header_len;
                                let chunk_end = current_pos + chunk_size;
                                if chunk_end <= n {
                                    log_info!("Processing chunk data", "size" => chunk_size, "data" => core::str::from_utf8(&buffer[current_pos..chunk_end]).unwrap_or("invalid utf8"));
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
                                    log_info!("Partial chunk", "available" => n - current_pos, "needed" => chunk_size);
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
                    log_error!("TLS read error", "error" => e);

                    let _ = tls_conn.close().await;

                    match e {
                        TlsError::ConnectionClosed => {
                            log_info!("Connection closed by server");
                            break 'retry_loop;
                        }
                        _ => {
                            if let Some(length) = content_length {
                                if bytes_received < length {
                                    log_warn!("Incomplete data received, retrying...",
                                        "received" => bytes_received,
                                        "total" => length
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
) -> Result<String, MenderStatus> {
    //log_info!("build_header_request");

    // For Cloudflare R2 storage URLs, use minimal headers
    if path.contains("cloudflarestorage.com") {
        let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
        request.push_str("Connection: close\r\n"); // Optional but recommended
        request.push_str("\r\n");

        log_info!("request", "request" => request);
        return Ok(request);
    }

    let host = extract_host(&config.host)?;
    let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
    request.push_str(&format!("Host: {}\r\n", host));
    request.push_str(&format!("User-Agent: {}\r\n", USER_AGENT));

    request.push_str("Connection: close\r\n"); // Optional but recommended

    // // Try with keep-alive instead of close
    // request.push_str("Connection: keep-alive\r\n");
    // request.push_str("Keep-Alive: timeout=30\r\n");  // 30 second keep-alive

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

    log_info!("request", "request" => request);
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
    log_info!("headers", "headers" => headers, "headers_end" => headers_end);
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
