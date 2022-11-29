use chacha20poly1305::aead::Aead;
use chacha20poly1305::*;
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::Rng;
use shared::Config;
use shared::EncryptedData;
use shared::Lifetime;
use std::collections::HashMap;
use uuid::Uuid;
use web_sys::console;

#[derive(Default)]
pub struct SecretShare {
    pub config: Config,
    pub encrypt_key: Option<String>,
    pub decrypt_key: Option<String>,

    pub drop_zone_active: bool,
    pub files: HashMap<String, (u128, Vec<u8>)>,
    pub file_buffer: HashMap<String, Vec<Vec<u8>>>,

    pub cryption_in_progress: Option<(u128, u128)>,

    pub clipboard_button_text: String,
    pub uuid: Option<Uuid>,
    pub error: Option<String>,
    pub password: String,
    pub lifetime: Lifetime,
    pub secret: Option<String>,
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

    pub fn decrypt(&self, data: EncryptedData) -> Vec<u8> {
        console::log_1(
            &format!(
                "Decrypt with key: {:?} nonce: {:?}",
                self.decrypt_key, data.nonce
            )
            .into(),
        );
        self.get_crypt()
            .decrypt(&self.binary_nonce(data.nonce).into(), data.data.as_ref())
            .expect("Could not decrypt")
    }

    fn generate_nonce(&self) -> String {
        thread_rng()
        .sample_iter(Alphanumeric)
        .take(24) // ChaCha20 needs key length of 24
        .map(char::from)
        .collect::<String>()
    }

    pub fn encrypt(&self, data: &[u8]) -> EncryptedData {
        let nonce = self.generate_nonce();

        console::log_1(
            &format!(
                "Encrypt with key: {:?} nonce: {:?}",
                self.encrypt_key, nonce
            )
            .into(),
        );
        let data = self.get_crypt()
            .encrypt(&self.binary_nonce(nonce.clone()).into(), data)
            .expect("Could not encrypt");
        EncryptedData{data, nonce}
    }

    pub fn to_binary(&self, key: String) -> Vec<u8> {
        key.chars().map(|c| c as u8).collect::<Vec<_>>()
    }

    pub fn binary_encrypt_key(&self) -> [u8; 32] {
        let key = self.encrypt_key.clone().expect("Not set");
        self.to_binary(key).try_into().expect("Wrong length")
    }

    pub fn binary_decrypt_key(&self) -> [u8; 32] {
        let key = self.decrypt_key.clone().expect("Not set");
        self.to_binary(key).try_into().expect("Wrong length")
    }

    pub fn binary_nonce(&self, nonce: String) -> [u8; 24] {
        self.to_binary(nonce).try_into().expect("Wrong length")
    }

    pub fn get_secret(&self) -> String {
        if let Some(secret) = &self.secret {
            secret.clone()
        } else {
            "".to_string()
        }
    }

    pub fn file_names(&self) -> Vec<(String, String)> {
        self.files
            .iter()
            .map(|(file_name, _)| {
                if file_name.len() > 35 {
                    let abbrev_name = file_name[0..35].to_string();
                    let ext = file_name[(file_name.len() - 3)..].to_string();
                    (file_name.clone(), format!("{}…{}", abbrev_name, ext))
                } else {
                    (file_name.clone(), file_name.clone())
                }
            })
            .collect()
    }

    pub fn get_crypt(&self) -> XChaCha20Poly1305 {
        if self.decrypt_key.is_some() {
            XChaCha20Poly1305::new((&self.binary_decrypt_key()).into())
        } else if self.encrypt_key.is_some() {
            XChaCha20Poly1305::new((&self.binary_encrypt_key()).into())
        } else {
            panic!("No en/decrypt key set")
        }
    }
}
