use std::fmt::Display;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct Password {
    salt: String,
    hash: String,
}
#[derive(Serialize, Deserialize)]
pub enum Request {
    CreateSecret {
        encrypted_secret: String,
        password: Option<Password>,
    },
    GetSecret{uuid: Uuid}
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    Error(String),
    Secret(String),
    Uuid(Uuid),
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub error: Option<String>,
    pub base_url: String,
    pub key_length: i32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            error: None,
            base_url: "".to_string(),
            key_length: 16,
        }
    }
}

impl Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(&self) {
            Ok(json) => {
                write!(f, "{}", &json)
            }
            Err(_err) => write!(f, "{{}}"),
        }
    }
}