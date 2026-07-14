use js_sys::{Array, Uint8Array};
use shared::EncryptedData;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{AesGcmParams, Crypto, CryptoKey};

const IV_LEN: usize = 12;

// Crypto: AES-256-GCM via the browser's SubtleCrypto. Runs off the main
// thread natively, so whole files are encrypted in a single call — no
// chunking, no workers.

fn crypto() -> Crypto {
    web_sys::window()
        .expect("no window")
        .crypto()
        .expect("WebCrypto unavailable")
}

fn err_str(e: JsValue) -> String {
    format!("Crypto error: {:?}", e)
}

async fn import_key(key: &str) -> Result<CryptoKey, String> {
    let usages = Array::of2(&"encrypt".into(), &"decrypt".into());
    let key_data = Uint8Array::from(key.as_bytes());
    let promise = crypto()
        .subtle()
        .import_key_with_str("raw", &key_data, "AES-GCM", false, &usages)
        .map_err(err_str)?;
    Ok(JsFuture::from(promise)
        .await
        .map_err(err_str)?
        .unchecked_into())
}

async fn encrypt_raw(key: &str, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key = import_key(key).await?;
    let mut iv = vec![0u8; IV_LEN];
    crypto()
        .get_random_values_with_u8_array(&mut iv)
        .map_err(err_str)?;
    let params = AesGcmParams::new("AES-GCM", &Uint8Array::from(iv.as_slice()));
    let mut data = plaintext.to_vec();
    let promise = crypto()
        .subtle()
        .encrypt_with_object_and_u8_array(&params, &key, &mut data)
        .map_err(err_str)?;
    let buffer = JsFuture::from(promise).await.map_err(err_str)?;
    Ok((Uint8Array::new(&buffer).to_vec(), iv))
}

async fn decrypt_raw(key: &str, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    let key = import_key(key).await?;
    let params = AesGcmParams::new("AES-GCM", &Uint8Array::from(iv));
    let mut data = ciphertext.to_vec();
    let promise = crypto()
        .subtle()
        .decrypt_with_object_and_u8_array(&params, &key, &mut data)
        .map_err(|_| "Could not decrypt".to_string())?;
    let buffer = JsFuture::from(promise)
        .await
        .map_err(|_| "Could not decrypt".to_string())?;
    Ok(Uint8Array::new(&buffer).to_vec())
}

/// Encrypt into the JSON wire format (secret text, file names).
pub async fn encrypt_data(key: &str, plaintext: &[u8]) -> Result<EncryptedData, String> {
    let (data, iv) = encrypt_raw(key, plaintext).await?;
    Ok(EncryptedData {
        data,
        nonce: hex::encode(iv),
    })
}

pub async fn decrypt_data(key: &str, encrypted: &EncryptedData) -> Result<Vec<u8>, String> {
    let iv = hex::decode(&encrypted.nonce).map_err(|_| "Invalid nonce".to_string())?;
    decrypt_raw(key, &encrypted.data, &iv).await
}

/// Encrypt into a self-contained blob (files): IV followed by ciphertext.
pub async fn encrypt_blob(key: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let (data, mut blob) = encrypt_raw(key, plaintext).await?;
    blob.extend(data);
    Ok(blob)
}

pub async fn decrypt_blob(key: &str, blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < IV_LEN {
        return Err("File too short".to_string());
    }
    let (iv, ciphertext) = blob.split_at(IV_LEN);
    decrypt_raw(key, ciphertext, iv).await
}
