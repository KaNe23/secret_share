use serde::{Deserialize, Serialize};
use std::fmt::Display;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub enum Request {
    CreateSecret {
        encrypted_secret: String,
        password: Option<String>,
        lifetime: Lifetime,
    },
    GetSecret {
        uuid: Uuid,
        password: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Lifetime {
    Days(i32),
    Hours(i32),
    Minutes(i32),
}

impl ToString for Lifetime {
    fn to_string(&self) -> String {
        match self {
            Lifetime::Days(amount) => format!("{}d", amount),
            Lifetime::Hours(amount) => format!("{}h", amount),
            Lifetime::Minutes(amount) => format!("{}m", amount),
        }
    }
}

impl Lifetime {
    pub fn long_string(&self) -> String {
        match self {
            Lifetime::Days(amount) => {
                if *amount > 1 {
                    format!("{} Days", amount)
                } else {
                    format!("{} Day", amount)
                }
            }
            Lifetime::Hours(amount) => {
                if *amount > 1 {
                    format!("{} Hours", amount)
                } else {
                    format!("{} Hour", amount)
                }
            }
            Lifetime::Minutes(amount) => {
                if *amount > 1 {
                    format!("{} Minutes", amount)
                } else {
                    format!("{} Minute", amount)
                }
            }
        }
    }

    pub fn to_seconds(&self) -> i32 {
        match self {
            Lifetime::Days(amount) => amount * 24 * 60 * 60,
            Lifetime::Hours(amount) => amount * 60 * 60,
            Lifetime::Minutes(amount) => amount * 60,
        }
    }
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
    pub lifetimes: Vec<Lifetime>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            error: "".to_string(),
            base_url: "".to_string(),
            key_length: 16,
            max_length: 10000,
            password_required: false,
            lifetimes: vec![Lifetime::Days(7)],
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
