use alloc::{boxed::Box, string::{String, ToString}, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use embassy_time::Duration;
use embedded_io_async::{Read, Write};
use embedded_tls::{TlsConnection, Aes128GcmSha256};
use embassy_net::tcp::TcpSocket;
use embedded_websocket::{
    WebSocket, WebSocketCloseStatusCode, WebSocketReceiveMessageType,
    WebSocketSendMessageType, WebSocketOptions, Client,
};
use esp_hal::rng::Trng;
use alloc::format;
use alloc::sync::Arc;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex as EmbassyMutex;

use crate::{
    log_error,
    mender_mcu_client::{
        core::mender_utils::{MenderStatus, MenderResult},
        platform::net::mender_http::connect_to_host,
    },
};

// Constants
pub const CONFIG_MENDER_WEBSOCKET_BUFFER_SIZE: usize = 1024;
pub const CONFIG_MENDER_WEBSOCKET_RECONNECT_TIMEOUT: u64 = 3000;
pub const CONFIG_MENDER_WEBSOCKET_NETWORK_TIMEOUT: u64 = 3000;
pub const CONFIG_MENDER_WEBSOCKET_REQUEST_TIMEOUT: u64 = 3000;
pub const CONFIG_MENDER_WEBSOCKET_PING_INTERVAL: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WebSocketEvent {
    Connected,
    DataReceived,
    Disconnected,
    Error,
}

#[derive(Clone)]
pub struct WebSocketConfig {
    pub host: String,
}

pub struct WebSocketStream<'a> {
    connection: Option<TlsConnection<'a, TcpSocket<'a>, Aes128GcmSha256>>,
    read_buffer: Vec<u8>,  // Changed to owned Vec
    write_buffer: Vec<u8>, // Changed to owned Vec
}

impl<'a> WebSocketStream<'a> {
    pub fn new(read_buffer: &[u8], write_buffer: &[u8]) -> Self {
        Self {
            connection: None,
            read_buffer: read_buffer.to_vec().into_boxed_slice(),
            write_buffer: write_buffer.to_vec().into_boxed_slice(),
        }
    }

    pub async fn connect(&'a mut self, url: &str) -> MenderResult<()> {
        let http_url = convert_ws_to_http_url(url)?;
        
        let connection = connect_to_host(
            &http_url,
            &mut self.read_buffer,
            &mut self.write_buffer,
        ).await?;
        
        self.connection = Some(connection);
        Ok(())
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> MenderResult<usize> {
        if let Some(conn) = &mut self.connection {
            conn.read(buf).await.map_err(|_| MenderStatus::Failed)
        } else {
            Err(MenderStatus::Failed)
        }
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> MenderResult<()> {
        if let Some(conn) = &mut self.connection {
            conn.write_all(buf).await.map_err(|_| MenderStatus::Failed)
        } else {
            Err(MenderStatus::Failed)
        }
    }

    pub async fn close(&mut self) -> MenderResult<()> {
        if let Some(connection) = self.connection.take() {
            let _ = connection.close().await;
        }
        Ok(())
    }

    pub async fn read_with_timeout(
        &mut self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> MenderResult<usize> {
        embassy_time::with_timeout(
            timeout,
            self.read(buf)
        ).await.map_err(|_| MenderStatus::Failed)?
    }

    pub async fn write_with_timeout(
        &mut self,
        buf: &[u8],
        timeout: Duration,
    ) -> MenderResult<()> {
        embassy_time::with_timeout(
            timeout,
            self.write_all(buf)
        ).await.map_err(|_| MenderStatus::Failed)?
    }
}

pub struct WebSocketHandle<'a> {
    websocket: WebSocket<Trng<'static>, Client>,
    stream: Option<WebSocketStream<'a>>,
    data: Option<Vec<u8>>,
    data_len: usize,
    callback: Box<dyn Fn(WebSocketEvent, Option<&[u8]>, Option<&[u8]>) -> MenderResult<()> + Send + Sync>,
    abort: AtomicBool,
    read_buffer: Arc<EmbassyMutex<NoopRawMutex, Vec<u8>>>,
    write_buffer: Arc<EmbassyMutex<NoopRawMutex, Vec<u8>>>,
}

// Global config
static WEBSOCKET_CONFIG: Mutex<CriticalSectionRawMutex, Option<WebSocketConfig>> = Mutex::new(None);

fn convert_ws_to_http_url(ws_url: &str) -> MenderResult<String> {
    if let Some(rest) = ws_url.strip_prefix("ws://") {
        Ok(format!("http://{}", rest))
    } else if let Some(rest) = ws_url.strip_prefix("wss://") {
        Ok(format!("https://{}", rest))
    } else {
        Ok(String::from(ws_url))
    }
}

pub async fn websocket_init(config: WebSocketConfig) -> MenderResult<()> {
    let mut conf = WEBSOCKET_CONFIG.lock().await;
    *conf = Some(config);
    Ok(())
}

pub async fn websocket_connect<'a>(
    rng: Trng<'static>,
    jwt: Option<&str>,
    path: &str,
    callback: impl Fn(WebSocketEvent, Option<&[u8]>, Option<&[u8]>) -> MenderResult<()> + Send + Sync + 'static,
) -> MenderResult<WebSocketHandle<'a>> {
    let config = WEBSOCKET_CONFIG.lock().await;
    let config = config.as_ref().ok_or(MenderStatus::Failed)?;

    // Construct WebSocket URL
    let url = if path.starts_with("ws://") || path.starts_with("wss://") {
        String::from(path)
    } else {
        let base_url = &config.host;
        if base_url.starts_with("http://") {
            format!("ws://{}{}", &base_url[7..], path)
        } else if base_url.starts_with("https://") {
            format!("wss://{}{}", &base_url[8..], path)
        } else {
            format!("{}{}", base_url, path)
        }
    };

    let host = url
        .split("://")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .ok_or(MenderStatus::Failed)?;

    let mut ws = WebSocket::<Trng<'static>, Client>::new_client(rng);

    let auth_header = jwt.map(|token| alloc::format!("Authorization: Bearer {}", token));
    let header_vec = auth_header.as_ref().map(|h| vec![h.as_str()]);
    let auth_header_slice = header_vec.as_ref().map(|v| v.as_slice());

    let mut handshake_buffer = vec![0u8; CONFIG_MENDER_WEBSOCKET_BUFFER_SIZE];

    let options = WebSocketOptions {
        path,
        host,
        origin: "",
        sub_protocols: None,
        additional_headers: auth_header_slice,
    };

    let (handshake_len, _key) = ws
        .client_connect(&options, &mut handshake_buffer)
        .map_err(|_| MenderStatus::Failed)?;

    // Create the buffers first
    let read_buffer = Arc::new(EmbassyMutex::<NoopRawMutex, Vec<u8>>::new(
        vec![0u8; CONFIG_MENDER_WEBSOCKET_BUFFER_SIZE]
    ));
    let write_buffer = Arc::new(EmbassyMutex::<NoopRawMutex, Vec<u8>>::new(
        vec![0u8; CONFIG_MENDER_WEBSOCKET_BUFFER_SIZE]
    ));

    // Shared buffers with `Arc<Mutex<_>>`
    let read_buffer_guard = read_buffer.lock().await;
    let write_buffer_guard = write_buffer.lock().await;
    
    let mut stream = WebSocketStream::new(
        &read_buffer_guard,
        &write_buffer_guard
    );

    // Connect and write in a separate scope to allow the stream to be moved
    {
        stream.connect(&url).await?;
        stream.write_all(&handshake_buffer[..handshake_len]).await?;
    }

    Ok(WebSocketHandle {
        websocket: ws,
        stream: Some(stream),
        data: None,
        data_len: 0,
        callback: Box::new(callback),
        abort: AtomicBool::new(false),
        read_buffer,
        write_buffer,
    })
}

impl<'a> WebSocketHandle<'a> {
    pub async fn run(&mut self) -> MenderResult<()> {
        let mut buffer = vec![0u8; CONFIG_MENDER_WEBSOCKET_BUFFER_SIZE];
        let mut output_buffer = vec![0u8; CONFIG_MENDER_WEBSOCKET_BUFFER_SIZE];

        while !self.abort.load(Ordering::Relaxed) {
            if let Some(stream) = &mut self.stream {
                match stream.read_with_timeout(
                    &mut buffer,
                    Duration::from_millis(CONFIG_MENDER_WEBSOCKET_NETWORK_TIMEOUT),
                ).await {
                    Ok(size) if size > 0 => {
                        let read_result = self.websocket.read(&buffer[..size], &mut output_buffer)
                            .map_err(|_| MenderStatus::Failed)?;
                        
                        match read_result.message_type {
                            WebSocketReceiveMessageType::Binary => {
                                if self.data.is_none() {
                                    (self.callback)(
                                        WebSocketEvent::DataReceived,
                                        Some(&output_buffer[..read_result.len_to]),
                                        None
                                    )?;
                                } else {
                                    if let Some(buf) = &mut self.data {
                                        buf.extend_from_slice(&output_buffer[..read_result.len_to]);
                                        self.data_len += read_result.len_to;
                                    }
                                }
                            }
                            WebSocketReceiveMessageType::Ping => {
                                // Send pong response
                                let mut pong_buffer = vec![0u8; 125];
                                let frame_len = self.websocket.write(
                                    WebSocketSendMessageType::Pong,
                                    true,
                                    &output_buffer[..read_result.len_to],
                                    &mut pong_buffer,
                                ).map_err(|_| MenderStatus::Failed)?;

                                stream.write_all(&pong_buffer[..frame_len]).await?;
                            }
                            WebSocketReceiveMessageType::Pong => {}
                            _ => {
                                if read_result.close_status.is_some() {
                                    (self.callback)(WebSocketEvent::Disconnected, None, None)?;
                                    break;
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        (self.callback)(WebSocketEvent::Disconnected, None, None)?;
                        break;
                    }
                    Err(_) => {
                        (self.callback)(WebSocketEvent::Error, None, None)?;
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn send(&mut self, data: &[u8]) -> MenderResult<()> {
        let mut buffer = vec![0u8; data.len() + 14]; // WebSocket frame overhead
        let frame_len = self.websocket.write(
            WebSocketSendMessageType::Binary,
            true,
            data,
            &mut buffer,
        ).map_err(|_| MenderStatus::Failed)?;

        if let Some(stream) = &mut self.stream {
            stream.write_with_timeout(
                &buffer[..frame_len],
                Duration::from_millis(CONFIG_MENDER_WEBSOCKET_REQUEST_TIMEOUT),
            ).await?;
        }
        Ok(())
    }
}

pub async fn websocket_disconnect(handle: &mut WebSocketHandle<'_>) -> MenderResult<()> {
    handle.abort.store(true, Ordering::Relaxed);

    let mut buffer = vec![0u8; 128];
    // Manually construct the close frame payload
    let close_code = 1000u16; // Normal closure close code
    let close_reason = b"";   // No specific reason

    let mut payload = Vec::with_capacity(2 + close_reason.len());
    payload.extend_from_slice(&close_code.to_be_bytes()); // Add close code
    payload.extend_from_slice(close_reason);             // Add close reason

    // Send the close frame as a binary message
    let frame_len = handle.websocket.write(
        WebSocketSendMessageType::Binary,
        true,          // Final fragment
        &payload,      // Payload with close code and reason
        &mut buffer,   // Buffer to hold the frame
    ).map_err(|_| MenderStatus::Failed)?;

    if let Some(stream) = &mut handle.stream {
        let _ = stream.write_all(&buffer[..frame_len]).await;
        let _ = stream.close().await;
    }

    (handle.callback)(WebSocketEvent::Disconnected, None, None)?;
    Ok(())
}

pub async fn websocket_exit() {
    let mut config = WEBSOCKET_CONFIG.lock().await;
    *config = None;
}