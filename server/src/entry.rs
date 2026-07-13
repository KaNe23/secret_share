use redis::{FromRedisValue, ParsingError, RedisWrite, ToRedisArgs, ToSingleRedisArg, Value};
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_string};
use shared::EncryptedData;
use std::collections::HashMap;
use std::str;

#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
    pub secret: EncryptedData,
    pub password: Option<String>,
    pub file_list: HashMap<String, u64>,
}

impl FromRedisValue for Entry {
    fn from_redis_value(v: Value) -> Result<Self, ParsingError> {
        match v {
            Value::Nil => Err("Not found".to_string().into()),
            Value::BulkString(data) => from_slice(&data)
                .map_err(|_| "Could not deserialize Entry".to_string().into()),
            // Okay and Int are good return values, but I have to return some kind of Entry anyway...
            Value::Okay | Value::Int(_) => Ok(Entry {
                secret: EncryptedData { data: vec![], nonce: "".to_string() },
                password: None,
                file_list: HashMap::new(),
            }),
            _ => Err(format!("Unexpected return type: {:?}", v).into()),
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
}

impl ToSingleRedisArg for Entry {}
