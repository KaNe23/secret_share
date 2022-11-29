use redis::{ErrorKind, FromRedisValue, RedisError, RedisResult, RedisWrite, ToRedisArgs, Value};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};
use shared::EncryptedData;
use std::collections::HashMap;
use std::str;

#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
    pub secret: EncryptedData,
    pub password: Option<String>,
    pub file_list: HashMap<String, u128>,
}

impl FromRedisValue for Entry {
    fn from_redis_value(v: &redis::Value) -> RedisResult<Self> {
        match v {
            Value::Nil => Err(RedisError::from((ErrorKind::ResponseError, "Not found"))),
            Value::Data(_data) => {
                let values: String = FromRedisValue::from_redis_value(v)?;
                if let Ok(entry) = from_str(&values) {
                    Ok(entry)
                } else {
                    Err(RedisError::from((
                        ErrorKind::TypeError,
                        "Could not deserialize Entry",
                    )))
                }
            }
            // Okay and Int are good return values, but I have to return some kind of Entry anyway...
            Value::Okay | Value::Int(_) => Ok(Entry {
                secret: EncryptedData { data: vec![], nonce: "".to_string() },
                password: None,
                file_list: HashMap::new(),
            }),
            _ => Err(RedisError::from((
                ErrorKind::ExtensionError,
                "",
                format!("Unexpected return type: {:?}", v),
            ))),
        }
    }
}

impl ToRedisArgs for Entry {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        let json = to_string(&self).expect("Could not serialize Entry");
        ToRedisArgs::write_redis_args(&json, out);
    }

    fn is_single_arg(&self) -> bool {
        false
    }
}
