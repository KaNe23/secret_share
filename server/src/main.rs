use acid_store::{
    repo::{value::ValueRepo, OpenOptions},
    Error,
};
use acid_store::{store::DirectoryStore, uuid::Uuid};
use actix_files as fs;
use actix_web::{
    get,
    middleware::Logger,
    post,
    web::{self, Json},
    App, HttpResponse, HttpServer, Responder,
};
use askama::Template;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, path::PathBuf, str::FromStr};

#[derive(Template)]
#[template(path = "index.html", escape = "none")]
struct IndexTemplate {
    json_config: Json<Config>,
}

#[derive(Serialize, Deserialize)]
struct Config {
    error: Option<String>,
    base_url: String,
}

impl Default for Config {
    fn default() -> Self {
        let base_url = match std::env::var("BASE_URL") {
            Ok(val) => val,
            Err(_e) => "https://set_base_url_env_var.example.com".to_string(),
        };

        Config {
            error: None,
            base_url,
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

#[get("/{uuid}")]
async fn index_uuid(web::Path(uuid): web::Path<String>) -> impl Responder {
    let key = match Uuid::from_str(&uuid) {
        Ok(key) => key,
        Err(_msg) => {
            return render_index_page(Some(
                "Invalid secret key (UUID), likely an incomplete link/url.".to_string(),
            ))
        }
    };

    match key_exists(key) {
        Ok(false) => {
            return render_index_page(Some("Secret not found or already viewed.".to_string()))
        }
        Err(msg) => return render_index_page(Some(format!("Error: {}", msg))),
        _ => render_index_page(None),
    }
}

fn render_index_page(error: Option<String>) -> impl Responder {
    let index_page = IndexTemplate {
        json_config: Json(Config {
            error,
            ..Config::default()
        }),
    };

    let body = index_page.render().unwrap();
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body)
}

#[get("/")]
async fn index() -> impl Responder {
    render_index_page(None)
}

#[post("/get_secret")]
async fn get_secret(params: web::Json<shared::Request>) -> impl Responder {
    let key = if let Json(shared::Request::GetSecret{uuid}) = params{
        uuid
    }else{
        return HttpResponse::BadRequest().finish();
    };

    let (mut store, secret) = match find_secret(key) {
        Ok((store, key)) => (store, key),
        Err(msg) => return HttpResponse::InternalServerError().body(format!("Error: {}", msg)),
    };

    store.remove(&key);

    if let Err(msg) = store.commit() {
        return HttpResponse::InternalServerError().body(format!("Error: {}", msg));
    }

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(secret)
}

#[post("/new_secret")]
async fn new_secret(params: web::Json<shared::Request>) -> impl Responder {
    let (secret, password) = if let Json(shared::Request::CreateSecret {
        encrypted_secret,
        password,
    }) = params
    {
        (encrypted_secret, password)
    } else {
        return HttpResponse::BadRequest().finish();
    };

    let mut store = match get_storage() {
        Ok(store) => store,
        Err(msg) => return HttpResponse::InternalServerError().body(format!("Error: {}", msg)),
    };

    let key = Uuid::new_v4();

    if let Err(msg) = store.insert(key, &secret) {
        return HttpResponse::InternalServerError().body(format!("Error: {}", msg));
    }

    if let Err(msg) = store.commit() {
        return HttpResponse::InternalServerError().body(format!("Error: {}", msg));
    }

    let response = shared::Response::Uuid(key);

    HttpResponse::Ok().json(response)
}

fn get_storage() -> Result<ValueRepo<Uuid, DirectoryStore>, Error> {
    // move location into env var
    let path = PathBuf::from("store");

    let store = DirectoryStore::new(path)?;
    OpenOptions::new(store).create::<ValueRepo<Uuid, _>>()
}

fn find_secret(key: Uuid) -> Result<(ValueRepo<Uuid, DirectoryStore>, String), Error> {
    let store = get_storage()?;
    let secret: String = store.get(&key)?;

    Ok((store, secret))
}

fn key_exists(key: Uuid) -> Result<bool, Error> {
    let store = get_storage()?;
    Ok(store.contains(&key))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    // for (key, var) in std::env::vars(){
    //     println!("key: {} val: {}", key, var);
    // }

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(index)
            .service(index_uuid)
            .service(new_secret)
            .service(get_secret)
            .service(fs::Files::new("/pkg", "client/pkg").show_files_listing())
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
