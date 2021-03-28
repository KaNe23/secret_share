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
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, str::FromStr};
use shared::{Request, Response, Config};

lazy_static! {
    static ref BASE_URL: String = if let Ok(base_url) = std::env::var("BASE_URL") {
        base_url
    } else {
        "http://localhost:8080".to_string()
    };
    static ref KEY_LENGTH: i32 = if let Ok(key_len) = std::env::var("KEY_LENGTH") {
        if let Ok(key_len) = i32::from_str(&key_len) {
            key_len
        } else {
            16
        }
    } else {
        16
    };
}

#[derive(Template)]
#[template(path = "index.html", escape = "none")]
struct IndexTemplate {
    json_config: Json<Config>,
}

#[get("/{uuid}")]
async fn index_uuid(web::Path(uuid): web::Path<String>) -> impl Responder {
    let key = match Uuid::from_str(&uuid) {
        Ok(key) => key,
        Err(_msg) => {
            return render_index_page(
                "Invalid secret key (UUID), likely an incomplete link/url.".to_string(),
                false,
            )
        }
    };

    match key_exists(key) {
        Ok(false) => {
            return render_index_page(
                "Secret not found or already viewed.".to_string(),
                false,
            )
        }
        Err(msg) => return render_index_page(format!("Error: {}", msg), false),
        _ => {}
    }

    match find_entry(key) {
        Ok((_uuid, entry)) => {
            if entry.password.is_some() {
                return render_index_page("".to_string(), true);
            } else {
                return render_index_page("".to_string(), false);
            }
        }
        Err(msg) => {
            return render_index_page(
                format!("Secret found but could not be fetched: {}", msg),
                false,
            )
        }
    }
}

fn render_index_page(error: String, password_required: bool) -> impl Responder {
    let index_page = IndexTemplate {
        json_config: Json(Config {
            error,
            base_url: BASE_URL.clone(),
            key_length: *KEY_LENGTH,
            password_required,
        }),
    };

    let body = index_page.render().unwrap();
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

    let (mut store, entry) = match find_entry(key) {
        Ok((store, key)) => (store, key),
        Err(msg) => return HttpResponse::Ok().json(Response::Error(format!("Error: {}", msg))),
    };

    if let Some(entry_password) = entry.password {
        match bcrypt::verify(password, &entry_password){
            Ok(false) => {
                return HttpResponse::Ok().json(Response::Error("Invalid password!".to_string()));
            }
            Err(msg) => {
                return HttpResponse::Ok().json(Response::Error(format!("Error while validating password: {}", msg)));
            }
            _ => {}
        }

    }

    store.remove(&key);

    if let Err(msg) = store.commit() {
        return HttpResponse::Ok().json(Response::Error(format!("Error: {}", msg)));
    }

    HttpResponse::Ok().json(Response::Secret(entry.secret))
}

#[post("/new_secret")]
async fn new_secret(params: web::Json<Request>) -> impl Responder {
    let (secret, password) = if let Json(Request::CreateSecret {
        encrypted_secret,
        password,
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

        (encrypted_secret, password)
    } else {
        return HttpResponse::BadRequest().finish();
    };

    let mut store = match get_storage() {
        Ok(store) => store,
        Err(msg) => return HttpResponse::InternalServerError().body(format!("Error: {}", msg)),
    };

    let key = Uuid::new_v4();

    println!("password: {:?}", password);

    if let Err(msg) = store.insert(key, &Entry { secret, password }) {
        return HttpResponse::InternalServerError().body(format!("Error: {}", msg));
    }

    if let Err(msg) = store.commit() {
        return HttpResponse::InternalServerError().body(format!("Error: {}", msg));
    }

    let response = Response::Uuid(key);

    HttpResponse::Ok().json(response)
}

#[derive(Serialize, Deserialize)]
struct Entry {
    secret: String,
    password: Option<String>,
}

fn get_storage() -> Result<ValueRepo<Uuid, DirectoryStore>, Error> {
    // move location into env var
    let path = PathBuf::from("store");

    let store = DirectoryStore::new(path)?;
    OpenOptions::new(store).create::<ValueRepo<Uuid, _>>()
}

fn find_entry(key: Uuid) -> Result<(ValueRepo<Uuid, DirectoryStore>, Entry), Error> {
    let store = get_storage()?;
    let entry: Entry = store.get(&key)?;

    Ok((store, entry))
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
