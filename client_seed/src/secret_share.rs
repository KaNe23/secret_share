use js_sys::{Array, Uint8Array};
use shared::Config;
use shared::EncryptedData;
use shared::Lifetime;
use std::collections::HashMap;
use uuid::Uuid;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{AesGcmParams, Crypto, CryptoKey};

const IV_LEN: usize = 12;

#[derive(Default)]
pub struct SecretShare {
    pub config: Config,
    pub encrypt_key: Option<String>,
    pub decrypt_key: Option<String>,

    pub drop_zone_active: bool,
    // plain file name -> (encrypted file name, size, content)
    pub files: HashMap<String, (String, u64, Vec<u8>)>,
    // pending transfers: (encrypted file name, plaintext bytes — empty for downloads)
    pub requests: Vec<(String, Vec<u8>)>,

    pub cryption_in_progress: Option<(u64, u64)>,

    pub clipboard_button_text: String,
    pub uuid: Option<Uuid>,
    pub error: Option<String>,
    pub password: String,
    pub lifetime: Lifetime,
    pub secret: Option<String>,
    pub blob_list: Vec<(String, String)>,
}

impl SecretShare {
    pub fn url(&self) -> String {
        format!(
            "{}/{}#{}",
            self.config.base_url,
            self.uuid.expect("No uuid set"),
            self.encrypt_key.as_ref().expect("No encrypt key set")
        )
    }

    pub fn key(&self) -> String {
        self.decrypt_key
            .clone()
            .or_else(|| self.encrypt_key.clone())
            .expect("No en/decrypt key set")
    }

    pub fn get_secret(&self) -> String {
        self.secret.clone().unwrap_or_default()
    }

    pub fn file_names(&self) -> Vec<(String, String)> {
        self.files
            .keys()
            .map(|file_name| {
                if file_name.chars().count() > 35 {
                    let abbrev_name: String = file_name.chars().take(35).collect();
                    let ext: String = file_name
                        .chars()
                        .skip(file_name.chars().count() - 3)
                        .collect();
                    (file_name.clone(), format!("{}…{}", abbrev_name, ext))
                } else {
                    (file_name.clone(), file_name.clone())
                }
            })
            .collect()
    }
}

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
