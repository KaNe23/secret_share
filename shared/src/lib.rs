use core::fmt;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Display, num::ParseIntError, str::FromStr};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct EncryptedData {
    pub data: Vec<u8>,
    pub nonce: String,
}

impl ToString for EncryptedData {
    fn to_string(&self) -> String {
        let data = hex::encode(&self.data);
        format!("{}.{}", data, self.nonce)
    }
}

#[derive(Debug)]
pub struct DecodeError;

impl FromStr for EncryptedData {
    type Err = DecodeError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let mut parts = string.split('.').into_iter();
        let data_part = parts.next();
        let nonce_part = parts.next();
        if data_part.is_some() && nonce_part.is_some() {
            let data = hex::decode(data_part.unwrap()).expect("Could not decode hex value");
            Ok(EncryptedData {
                data,
                nonce: nonce_part.unwrap().to_string(),
            })
        } else {
            Err(DecodeError)
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum Request {
    CreateSecret {
        secret: EncryptedData,
        password: Option<String>,
        lifetime: Lifetime,
        // file_list: HashMap<String, u128>,
        file_list: HashMap<String, u128>,
    },
    SendFileChunk {
        uuid: Uuid,
        file_name: EncryptedData,
        chunk_index: usize,
        chunk: EncryptedData,
    },
    GetFileChunk {
        uuid: Uuid,
        file_name: String,
        chunk_index: usize,
    },
    GetSecret {
        uuid: Uuid,
        password: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Copy)]
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

impl Default for Lifetime {
    fn default() -> Lifetime {
        Self::Days(7)
    }
}

#[derive(Debug, Clone)]
pub struct LifetimeParseError;

impl fmt::Display for LifetimeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Could not parse liftime")
    }
}

impl From<ParseIntError> for LifetimeParseError {
    fn from(_: ParseIntError) -> Self {
        LifetimeParseError
    }
}

impl FromStr for Lifetime {
    type Err = LifetimeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let unit = s.chars().last().ok_or(LifetimeParseError)?;

        let number = s.trim_end_matches(unit);
        let amount = i32::from_str(number)?;

        match unit {
            'd' => Ok(Lifetime::Days(amount)),
            'h' => Ok(Lifetime::Hours(amount)),
            'm' => Ok(Lifetime::Minutes(amount)),
            _ => Err(LifetimeParseError),
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

#[derive(Serialize, Deserialize, Clone)]
pub struct FileChunk {
    pub file_name: EncryptedData,
    pub index: usize,
    pub chunk: EncryptedData,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Response {
    Error(String),
    Secret((EncryptedData, Vec<(String, usize)>)),
    FileChunk(FileChunk),
    Uuid(Uuid),
    Ok,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub error: String,
    pub info: String,
    pub base_url: String,
    pub key_length: i32,
    pub max_length: i32,
    pub password_required: bool,
    pub lifetimes: Vec<Lifetime>,
    pub max_files: i32,
    pub max_files_size: u128,
    pub chunk_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            error: "".to_string(),
            info: "".to_string(),
            base_url: "".to_string(),
            key_length: 16,
            max_length: 10000,
            password_required: false,
            lifetimes: vec![Lifetime::Days(7)],
            max_files: 5,
            max_files_size: byte_unit::n_mib_bytes!(25),
            chunk_size: 123_456 * 4,
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
