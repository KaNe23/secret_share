use core::fmt;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, num::ParseIntError, str::FromStr};
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
pub enum Response {
    Error(String),
    Secret(String),
    Uuid(Uuid),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub error: String,
    pub base_url: String,
    pub key_length: i32,
    pub max_length: i32,
    pub password_required: bool,
    pub lifetimes: Vec<Lifetime>,
    pub max_files: i32,
    pub max_files_size: u128,
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
            max_files: 5,
            max_files_size: byte_unit::n_mib_bytes!(25),
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
