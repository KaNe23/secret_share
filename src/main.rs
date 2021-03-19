use actix_web::{get, web, App, HttpServer, Responder};
use askama::Template;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a>{
    name: &'a str,
}

#[get("/{name}")]
async fn index(web::Path(name): web::Path<String>) -> impl Responder {
    // format!("Hello World!")
    let index = IndexTemplate{name: &name};
    index.render().unwrap()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(||
        App::new()
        .service(index))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}