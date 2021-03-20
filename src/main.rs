use std::{path::PathBuf, str::FromStr};

use actix_web::{get, middleware::Logger, post, web, App, HttpResponse, HttpServer, Responder};
use askama::Template;
use serde::{Deserialize, Serialize};
use acid_store::{store::DirectoryStore, uuid::Uuid};
use acid_store::repo::{OpenOptions, value::ValueRepo};
use acid_store::uuid;

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
    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(body)
}

#[get("/{uuid}")]
async fn get_secret(web::Path(uuid): web::Path<String>) -> impl Responder {
    let mut store = get_storage();

    // for key in store.keys(){
    //     let val: String = store.get(&key).unwrap();
    //     println!("Key: {} Value: {}", key, val);
    // }

    let key = Uuid::from_str(&uuid).unwrap();

    let secret: String = store.get(&key).unwrap();

    store.remove(&key);

    let _res = store.commit();

    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(secret)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Secret {
    secret: String,
}

#[post("/new_secret")]
async fn new_secret(params: web::Form<Secret>) -> impl Responder {
    println!("{:?}", params);

    let mut store = get_storage();


    let key = Uuid::new_v4();

    let res = store.insert(key, &params.secret);

    println!("{:?}", res);

    for key in store.keys(){
        println!("{}", key);
    }

    let _res = store.commit();

    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(key.to_string())
}

fn get_storage() -> ValueRepo<Uuid, DirectoryStore>{
    let mut path = PathBuf::new();
    path.push("store");

    let store = DirectoryStore::new(path).unwrap();
    OpenOptions::new(store).create::<ValueRepo<Uuid, _>>().unwrap()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    HttpServer::new(||
        App::new().wrap(Logger::default())
                  .service(index)
                  .service(new_secret)
                  .service(get_secret)
                  .data(web::Form::<Secret>::configure(|cfg| cfg.limit(256 * 1024)))
        )
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
