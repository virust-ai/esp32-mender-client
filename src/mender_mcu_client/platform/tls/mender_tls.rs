use crate::mender_mcu_client::mender_prj_config::{TLS_PRIVATE_KEY_LENGTH, TLS_PUBLIC_KEY_LENGTH};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use core::fmt::Write;
use core::str;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use esp_hal::rng::Trng;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{
    pkcs8::EncodePrivateKey, pkcs8::EncodePublicKey, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};

use crate::mender_mcu_client::core::mender_utils::{MenderResult, MenderStatus};
use crate::mender_mcu_client::platform::storage::mender_storage;
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};

// Constants for RSA key operations
const RSA_KEY_BITS: usize = 1024;

// Constants for PEM formatting
const PEM_BEGIN_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----";
const PEM_END_PUBLIC_KEY: &str = "-----END PUBLIC KEY-----";

// Global storage for keys
pub static PRIVATE_KEY: Mutex<CriticalSectionRawMutex, Option<Vec<u8>>> = Mutex::new(None);
static PUBLIC_KEY: Mutex<CriticalSectionRawMutex, Option<Vec<u8>>> = Mutex::new(None);

pub fn mender_tls_init() -> MenderResult<()> {
    // Nothing to do
    Ok((MenderStatus::Ok, ()))
}

pub async fn mender_tls_init_authentication_keys(
    rng: &mut Trng<'static>,
    recommissioning: bool,
) -> MenderResult<()> {
    log_info!("mender_tls_init_authentication_keys");
    // Clear existing keys
    *PRIVATE_KEY.lock().await = None;
    *PUBLIC_KEY.lock().await = None;

    // Handle recommissioning
    if recommissioning {
        log_info!("Delete authentication keys...");
        mender_storage::mender_storage_delete_authentication_keys()
            .await
            .map_err(|_| MenderStatus::Failed)?;
    }

    // Try to get existing keys or generate new ones
    match mender_storage::mender_storage_get_authentication_keys().await {
        Ok((MenderStatus::Ok, (priv_key, pub_key))) => {
            *PRIVATE_KEY.lock().await = Some(priv_key);
            *PUBLIC_KEY.lock().await = Some(pub_key);
        }
        Ok((_, _)) => {
            log_error!("Should not happen this case");
            return Err(MenderStatus::Failed);
        }
        Err(_) => {
            // Generate new keys
            mender_tls_generate_authentication_keys(rng).await?;

            // Store the new keys
            let priv_key = PRIVATE_KEY.lock().await.clone().unwrap_or_default();
            let pub_key = PUBLIC_KEY.lock().await.clone().unwrap_or_default();

            mender_storage::mender_storage_set_authentication_keys(&priv_key, &pub_key)
                .await
                .map_err(|_| MenderStatus::Failed)?;
        }
    }

    Ok((MenderStatus::Ok, ()))
}

async fn mender_tls_generate_authentication_keys(rng: &mut Trng<'static>) -> MenderResult<()> {
    log_info!("Generating new authentication keys...");

    // Generate RSA key pair
    let private_key = RsaPrivateKey::new(rng, RSA_KEY_BITS).map_err(|e| {
        log_error!("RSA key generation failed, {}", e);
        MenderStatus::Failed
    })?;

    let public_key = RsaPublicKey::from(&private_key);

    // Export keys in PKCS8 DER format
    let priv_key = private_key
        .to_pkcs8_der()
        .map_err(|e| {
            log_error!("Unable to export private key, {}", e);
            MenderStatus::Failed
        })?
        .as_bytes()
        .to_vec();

    let pub_key = public_key
        .to_public_key_der()
        .map_err(|e| {
            log_error!("Unable to export public key, {}", e);
            MenderStatus::Failed
        })?
        .as_bytes()
        .to_vec();

    // Validate key sizes
    if priv_key.len() > TLS_PRIVATE_KEY_LENGTH as usize {
        log_error!(
            "Private key too large, length: {}, max: {}",
            priv_key.len(),
            TLS_PRIVATE_KEY_LENGTH
        );
        return Err(MenderStatus::Failed);
    }
    if pub_key.len() > TLS_PUBLIC_KEY_LENGTH as usize {
        log_error!(
            "Public key too large, length: {}, max: {}",
            pub_key.len(),
            TLS_PUBLIC_KEY_LENGTH
        );
        return Err(MenderStatus::Failed);
    }

    // Store keys in global storage
    *PRIVATE_KEY.lock().await = Some(priv_key);
    *PUBLIC_KEY.lock().await = Some(pub_key);

    log_info!("Authentication keys generated successfully");
    Ok((MenderStatus::Ok, ()))
}

pub async fn mender_tls_sign_payload(payload: &str) -> MenderResult<String> {
    log_info!("mender_tls_sign_payload");

    // Get private key
    let priv_key_der = PRIVATE_KEY.lock().await.clone().ok_or_else(|| {
        log_error!("Private key not found");
        MenderStatus::NotFound
    })?;

    // Parse PKCS#8 DER format for RSA key
    let private_key = RsaPrivateKey::from_pkcs8_der(&priv_key_der).map_err(|e| {
        log_error!("Unable to parse private key, error: {}", e);
        MenderStatus::Failed
    })?;

    // Compute SHA256 digest
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let digest = hasher.finalize();

    // Sign the digest
    let signature = private_key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
        .map_err(|e| {
            log_error!("Unable to sign payload, error: {}", e);
            MenderStatus::Failed
        })?;

    // Base64 encode
    let b64_sig = base64_no_std_encode(&signature);

    log_info!("Signature generated successfully");
    Ok((MenderStatus::Ok, b64_sig))
}

// Base64 encode function remains unchanged
fn base64_no_std_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let len = ((input.len() + 2) / 3) * 4;
    let mut output = String::with_capacity(len);

    for chunk in input.chunks(3) {
        let b1 = chunk[0];
        let b2 = chunk.get(1).copied().unwrap_or(0);
        let b3 = chunk.get(2).copied().unwrap_or(0);

        let triple = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);

        let i1 = (triple >> 18) & 0x3F;
        let i2 = (triple >> 12) & 0x3F;
        let i3 = (triple >> 6) & 0x3F;
        let i4 = triple & 0x3F;

        output.push(ALPHABET[i1 as usize] as char);
        output.push(ALPHABET[i2 as usize] as char);

        if chunk.len() > 1 {
            output.push(ALPHABET[i3 as usize] as char);
        } else {
            output.push('=');
        }

        if chunk.len() > 2 {
            output.push(ALPHABET[i4 as usize] as char);
        } else {
            output.push('=');
        }
    }

    output
}

pub async fn mender_tls_get_public_key_pem() -> MenderResult<String> {
    log_info!("mender_tls_get_public_key_pem");
    // Get public key
    let pub_key = PUBLIC_KEY.lock().await.clone().ok_or_else(|| {
        log_error!("Public key not found");
        MenderStatus::NotFound
    })?;
    //log_info!("pub_key", "pub_key" => pub_key);

    // Convert DER to PEM
    mender_tls_pem_write_buffer(&pub_key).map_err(|_| {
        log_error!("Unable to convert public key to PEM");
        MenderStatus::Failed
    })
}

fn mender_tls_pem_write_buffer(der_data: &[u8]) -> MenderResult<String> {
    // Encode to base64 first
    let encoded_length = ((der_data.len() + 2) / 3) * 4;
    let mut b64_buf = vec![0u8; encoded_length];

    let actual_length = STANDARD
        .encode_slice(der_data, &mut b64_buf)
        .map_err(|_| MenderStatus::Failed)?;

    let b64_data =
        String::from_utf8(b64_buf[..actual_length].to_vec()).map_err(|_| MenderStatus::Failed)?;

    // Pre-calculate capacity
    let line_length = 64;
    let num_lines = b64_data.len().div_ceil(line_length);
    let capacity = PEM_BEGIN_PUBLIC_KEY.len() + 1 + // BEGIN tag + newline
        PEM_END_PUBLIC_KEY.len() + 1 +   // END tag + newline
        b64_data.len() +
        num_lines; // newlines for base64 content

    let mut pem = String::with_capacity(capacity);

    // Write header
    writeln!(pem, "{}", PEM_BEGIN_PUBLIC_KEY).map_err(|_| MenderStatus::Failed)?;

    // Write base64 in lines
    for chunk in b64_data.as_bytes().chunks(line_length) {
        writeln!(
            pem,
            "{}",
            core::str::from_utf8(chunk).map_err(|_| MenderStatus::Failed)?
        )
        .map_err(|_| MenderStatus::Failed)?;
    }

    // Write footer
    writeln!(pem, "{}", PEM_END_PUBLIC_KEY).map_err(|_| MenderStatus::Failed)?;

    Ok((MenderStatus::Ok, pem))
}

pub async fn mender_tls_exit() -> MenderResult<()> {
    *PRIVATE_KEY.lock().await = None;
    *PUBLIC_KEY.lock().await = None;
    Ok((MenderStatus::Ok, ()))
}
