use std::{ops::Add, path::PathBuf, str::FromStr};
use acid_store::repo::{value::ValueRepo, OpenOptions};
use acid_store::{store::DirectoryStore, uuid::Uuid};
use actix_web::{
    get, middleware::Logger, post, web, App, FromRequest, HttpResponse, HttpServer, Responder,
};
use askama::Template;
use serde::{Deserialize, Serialize};

#[derive(Template)]
#[template(path = "index.html", escape = "none")]
struct IndexTemplate<'a> {
    body: &'a NewSecretTemplate,
}

#[derive(Template)]
#[template(path = "new_secret.html")]
struct NewSecretTemplate {}

#[get("/")]
async fn index() -> impl Responder {
    let new_secret_template = NewSecretTemplate {};
    let index = IndexTemplate {
        body: &new_secret_template,
    };
    let body = index.render().unwrap();
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body)
}

#[get("/{uuid}")]
async fn get_secret(web::Path(uuid): web::Path<String>) -> impl Responder {
    let mut store = match get_storage(){
        Ok(store) => store,
        Err(msg) => return HttpResponse::InternalServerError().body(format!("Error: {}", msg)),
    };

    let key = match Uuid::from_str(&uuid) {
        Ok(key) => key,
        Err(msg) => return HttpResponse::InternalServerError().body(format!("Error: {}", msg)),
    };

    let secret: String = match store.get(&key) {
        Ok(secret) => secret,
        Err(msg) => return HttpResponse::NotFound().body(format!("Error: {}", msg)),
    };

    store.remove(&key);

    if let Err(msg) = store.commit() {
        return HttpResponse::InternalServerError().body(format!("Error: {}", msg));
    }

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(secret)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Secret {
    secret: String,
}

#[post("/new_secret")]
async fn new_secret(params: web::Form<Secret>) -> impl Responder {
    let mut store = match get_storage(){
        Ok(store) => store,
        Err(msg) => return HttpResponse::InternalServerError().body(format!("Error: {}", msg)),
    };

    let key = Uuid::new_v4();

    if let Err(msg) = store.insert(key, &params.secret) {
        return HttpResponse::InternalServerError().body(format!("Error: {}", msg));
    }

    if let Err(msg) = store.commit() {
        return HttpResponse::InternalServerError().body(format!("Error: {}", msg));
    }

    if let Ok(mut base_url) = std::env::var("BASE_URL") {
        base_url = base_url.add("/").add(&key.to_string());
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(base_url)
    } else {
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(key.to_string())
    }
}

fn get_storage() -> Result<ValueRepo<Uuid, DirectoryStore>, acid_store::Error> {
    let mut path = PathBuf::new();
    path.push("store");

    let store = DirectoryStore::new(path)?;
    OpenOptions::new(store).create::<ValueRepo<Uuid, _>>()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("BASE_URL", "localhost:8080");
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(index)
            .service(new_secret)
            .service(get_secret)
            .data(web::Form::<Secret>::configure(|cfg| cfg.limit(256 * 1024)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
