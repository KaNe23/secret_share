use serde::{Deserialize, Serialize};
use std::fmt::Display;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub enum Request {
    CreateSecret {
        encrypted_secret: String,
        password: Option<String>,
    },
    GetSecret {
        uuid: Uuid,
        password: String,
    },
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    Error(String),
    Secret(String),
    Uuid(Uuid),
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub error: String,
    pub base_url: String,
    pub key_length: i32,
    pub max_length: i32,
    pub password_required: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            error: "".to_string(),
            base_url: "".to_string(),
            key_length: 16,
            max_length: 10000,
            password_required: false,
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
