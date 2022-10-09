use actix_files::Files;
use actix_web::{
    get,
    middleware::Logger,
    post,
    web::{self, Json},
    App, HttpResponse, HttpServer, Responder,
};
use anyhow::{Error, Result};
use askama::Template;
use lazy_static::lazy_static;
use redis::{
    aio::Connection, AsyncCommands, Client, ErrorKind, FromRedisValue, RedisError, RedisResult,
    RedisWrite, ToRedisArgs, Value,
};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};
use shared::{Config, Lifetime, Request, Response};
use std::str;
use std::{collections::HashMap, str::FromStr};
use uuid::Uuid;

lazy_static! {
    static ref REDIS_HOST: String = if let Ok(redis_host) = std::env::var("REDIS_HOST") {
        format!("redis://{}/", redis_host)
    } else {
        "redis://127.0.0.1/".to_string()
    };

    static ref MAX_LENGTH: i32 = std::env::var("MAX_LENGTH").ok().and_then(|max_length| max_length.parse().ok()).unwrap_or(10000);

    static ref BASE_URL: String = if let Ok(base_url) = std::env::var("BASE_URL") {
        base_url
    } else {
        "http://localhost:8080".to_string()
    };

    static ref PORT: String = if let Ok(port) = std::env::var("PORT") {
        port
    } else {
        "8080".to_string()
    };

    static ref KEY_LENGTH: i32 = std::env::var("KEY_LENGTH").ok()
        .and_then(|key_len| i32::from_str(&key_len).ok())
        .unwrap_or(16);

    static ref DEFAULT_LIFETIMES: Vec<Lifetime> = vec![
        Lifetime::Days(7),
        Lifetime::Days(3),
        Lifetime::Days(1),
        Lifetime::Hours(12),
        Lifetime::Hours(4),
        Lifetime::Hours(1),
        Lifetime::Minutes(30),
        Lifetime::Minutes(5),
    ];

    static ref MAX_FILES: i32 = std::env::var("MAX_FILES").ok()
        .and_then(|max_files| i32::from_str(&max_files).ok())
        .unwrap_or(5);

    static ref MAX_FILES_SIZE: u128 = std::env::var("MAX_FILES_SIZE").ok()
        .and_then(|max_files_size| byte_unit::Byte::from_str(max_files_size).ok())
        .and_then(|max_files_size| Some(max_files_size.get_bytes()))
        .unwrap_or(byte_unit::n_mib_bytes!(25));

    // static ref LIFETIMES: Vec<String> = DEFAULT_LIFETIMES.iter().map(|ele| ele.0.clone()).collect::<Vec<String>>();
}

#[cfg(all(feature = "frontend-yew", feature = "frontend-seed"))]
compile_error!(
    "feature \"frontend-yew\" and feature \"frontend-seed\" cannot be enabled at the same time"
);

#[cfg(not(any(feature = "frontend-yew", feature = "frontend-seed")))]
compile_error!(
    "Either feature \"frontend-yew\" or \"frontend-seed\" must be enabled for this crate."
);

cfg_if::cfg_if! {
    if #[cfg(feature = "frontend-yew")] {
        #[derive(Template)]
        #[template(path = "index.html", escape = "none", config = "askama.toml")]
        struct IndexTemplate {
            json_config: Json<Config>,
        }
    } else if #[cfg(feature = "frontend-seed")] {
        #[derive(Template)]
        #[template(path = "index.html", escape = "none", config = "askama_seed.toml")]
        struct IndexTemplate {
            json_config: Json<Config>,
        }
    }
}

#[get("/{uuid}")]
async fn index_uuid(uuid: web::Path<String>) -> impl Responder {
    let key = match Uuid::from_str(&uuid) {
        Ok(key) => key,
        Err(_msg) => {
            return render_index_page(
                "Invalid secret key (UUID), likely an incomplete link/url.".to_string(),
                false,
            )
        }
    };

    match key_exists(key).await {
        Ok(false) => {
            return render_index_page(
                "Secret expired, not found or already viewed.".to_string(),
                false,
            )
        }
        Err(msg) => return render_index_page(format!("Error: {}", msg), false),
        _ => {}
    }

    match find_entry(key).await {
        Ok((_uuid, entry)) => {
            if entry.password.is_some() {
                render_index_page("".to_string(), true)
            } else {
                render_index_page("".to_string(), false)
            }
        }
        Err(msg) => render_index_page(
            format!("Secret found but could not be fetched: {}", msg),
            false,
        ),
    }
}

fn render_index_page(error: String, password_required: bool) -> impl Responder {
    let index_page = IndexTemplate {
        json_config: Json(Config {
            error,
            base_url: BASE_URL.clone(),
            key_length: *KEY_LENGTH,
            max_length: *MAX_LENGTH,
            password_required,
            lifetimes: DEFAULT_LIFETIMES.clone(),
            max_files: *MAX_FILES,
            max_files_size: *MAX_FILES_SIZE,
        }),
    };

    let body = index_page.render().expect("Could not render index page.");
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body)
}

#[get("/")]
async fn index() -> impl Responder {
    render_index_page("".to_string(), false)
}

#[post("/get_secret")]
async fn get_secret(params: web::Json<Request>) -> impl Responder {
    let (key, password) = if let Json(Request::GetSecret { uuid, password }) = params {
        (uuid, password)
    } else {
        return HttpResponse::Ok().json(Response::Error("Invalid request!".to_string()));
    };

    let (mut store, entry) = match find_entry(key).await {
        Ok((store, key)) => (store, key),
        Err(msg) => return HttpResponse::Ok().json(Response::Error(format!("Error: {}", msg))),
    };

    if let Some(entry_password) = entry.password {
        match bcrypt::verify(password, &entry_password) {
            Ok(false) => {
                return HttpResponse::Ok().json(Response::Error("Invalid password!".to_string()));
            }
            Err(msg) => {
                return HttpResponse::Ok().json(Response::Error(format!(
                    "Error while validating password: {}",
                    msg
                )));
            }
            _ => {}
        }
    }

    let result: redis::RedisResult<Entry> = store.del(&key.to_string()).await;

    if let Err(msg) = result {
        return HttpResponse::InternalServerError().body(format!("Error: {}", msg));
    }

    HttpResponse::Ok().json(Response::Secret(entry.secret))
}

#[post("/file_chunk")]
async fn file_chunk(params: web::Json<Request>) -> impl Responder {
    let (uuid, file_name, chunk_index, chunk) = if let Json(Request::SendFileChunk {
        uuid,
        file_name,
        chunk_index,
        chunk,
    }) = params
    {
        (uuid, file_name, chunk_index, chunk)
    } else {
        return HttpResponse::BadRequest().finish();
    };

    println!(
        "Uuid: {}, File: {}, Index: {}, Data: {}",
        uuid,
        file_name,
        chunk_index,
        chunk.len()
    );

    HttpResponse::Ok().json(Response::Ok)
}

#[post("/new_secret")]
async fn new_secret(params: web::Json<Request>) -> impl Responder {
    let (secret, password, lifetime, file_list) = if let Json(Request::CreateSecret {
        encrypted_secret,
        password,
        lifetime,
        file_list,
    }) = params
    {
        let password = if let Some(password) = password {
            // randomly choose cost of 5
            if let Ok(result) = bcrypt::hash(password, 5) {
                Some(result)
            } else {
                return HttpResponse::InternalServerError().body("Error: Unable to hash password.");
            }
        } else {
            None
        };

        (encrypted_secret, password, lifetime, file_list)
    } else {
        return HttpResponse::BadRequest().finish();
    };

    let lifetime = if DEFAULT_LIFETIMES.contains(&lifetime) {
        lifetime.to_seconds()
    } else {
        return HttpResponse::InternalServerError().body("Error: Invalid Lifetime");
    };

    let mut store = match get_storage().await {
        Ok(store) => store,
        Err(msg) => return HttpResponse::InternalServerError().body(format!("Error: {}", msg)),
    };

    let key = Uuid::new_v4();

    let result: RedisResult<Entry> = store
        .set(
            key.to_string(),
            Entry {
                secret,
                password,
                file_list,
            },
        )
        .await;

    if let Err(msg) = result {
        return HttpResponse::InternalServerError().body(format!("Error: {}", msg));
    }

    let result: RedisResult<Entry> = store.expire(key.to_string(), lifetime as usize).await;

    if let Err(msg) = result {
        return HttpResponse::InternalServerError().body(format!("Error: {}", msg));
    }

    let response = Response::Uuid(key);

    HttpResponse::Ok().json(response)
}

#[derive(Serialize, Deserialize)]
struct Entry {
    secret: String,
    password: Option<String>,
    file_list: HashMap<String, u128>,
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
                secret: "".to_string(),
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

async fn get_storage() -> Result<Connection, Error> {
    let client = Client::open(REDIS_HOST.clone())?;
    let connection = client.get_async_std_connection().await?;
    Ok(connection)
}

async fn find_entry(key: Uuid) -> Result<(Connection, Entry), Error> {
    let mut store = get_storage().await?;
    let entry: Entry = store.get(key.to_string()).await?;
    Ok((store, entry))
}

async fn key_exists(key: Uuid) -> Result<bool, Error> {
    let mut store = get_storage().await?;
    Ok(store.exists(&key.to_string()).await?)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    // for (key, var) in std::env::vars(){
    //     println!("key: {} val: {}", key, var);
    // }

    let adress = format!("0.0.0.0:{}", *PORT);

    println!("Listening on: {}", adress);

    HttpServer::new(|| {
        let app = App::new()
            .wrap(Logger::default())
            .service(index)
            .service(index_uuid)
            .service(new_secret)
            .service(get_secret)
            .service(file_chunk);

        #[cfg(feature = "frontend-yew")]
        let app = app.service(Files::new("/pkg", "./client/dist/").prefer_utf8(true));
        #[cfg(feature = "frontend-seed")]
        let app = app.service(Files::new("/pkg", "./client_seed/dist/").prefer_utf8(true));

        app
    })
    .bind(adress)?
    .run()
    .await
}
