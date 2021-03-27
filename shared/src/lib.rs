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
