mod storage;

use actix_files::Files;
use actix_web::{
    get, middleware,
    middleware::Compress,
    middleware::Logger,
    post,
    web::{self, Json},
    App, HttpResponse, HttpServer, Responder,
};
use askama::Template;
use byte_unit::Byte;
use redb::Database;
use shared::{Config, Lifetime, Request, Response};
use std::str::FromStr;
use std::sync::LazyLock;
use uuid::Uuid;

use crate::storage::{Entry, Take};

fn env_or<T: FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

static DB_PATH: LazyLock<String> =
    LazyLock::new(|| env_or("DB_PATH", "secret_share.redb".to_string()));
static MAX_LENGTH: LazyLock<i32> = LazyLock::new(|| env_or("MAX_LENGTH", 10000));
static BASE_URL: LazyLock<String> =
    LazyLock::new(|| env_or("BASE_URL", "http://localhost:8080".to_string()));
static PORT: LazyLock<String> = LazyLock::new(|| env_or("PORT", "8080".to_string()));
static KEY_LENGTH: LazyLock<i32> = LazyLock::new(|| env_or("KEY_LENGTH", 16));
static MAX_FILES: LazyLock<i32> = LazyLock::new(|| env_or("MAX_FILES", 5));
// e.g. MAX_FILES_SIZE="50 MB" / "1GiB" / "25mb"
static MAX_FILES_SIZE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("MAX_FILES_SIZE")
        .ok()
        .and_then(|max_files_size| Byte::parse_str(&max_files_size, true).ok())
        .map(|max_files_size| max_files_size.as_u64())
        .unwrap_or(25 * 1024 * 1024)
});
static DEFAULT_LIFETIMES: LazyLock<Vec<Lifetime>> = LazyLock::new(|| {
    vec![
        Lifetime::Days(7),
        Lifetime::Days(3),
        Lifetime::Days(1),
        Lifetime::Hours(12),
        Lifetime::Hours(4),
        Lifetime::Hours(1),
        Lifetime::Minutes(30),
        Lifetime::Minutes(5),
    ]
});

#[derive(Template)]
#[template(path = "index.html", escape = "none", config = "askama.toml")]
struct IndexTemplate {
    json_config: Json<Config>,
}

#[get("/{uuid}")]
async fn index_uuid(db: web::Data<Database>, uuid: web::Path<String>) -> impl Responder {
    let key = match Uuid::from_str(&uuid) {
        Ok(key) => key,
        Err(_msg) => {
            return render_index_page(
                "Invalid secret key (UUID), likely an incomplete link/url.".to_string(),
                "".into(),
                false,
            )
        }
    };

    match storage::get_entry(&db, &key.to_string()) {
        Ok(None) => render_index_page(
            "Secret expired, not found or already viewed.".to_string(),
            "".into(),
            false,
        ),
        Ok(Some(entry)) => {
            let file_info = if !entry.file_list.is_empty() {
                let size = entry.file_list.iter().fold(0, |acc, (_, size)| acc + size);
                let size = Byte::from_u64(size).get_appropriate_unit(byte_unit::UnitType::Binary);
                format!(
                    "{} files(s) attached, accumulated size: {}",
                    entry.file_list.len(),
                    size
                )
            } else {
                "No files attached.".into()
            };
            if entry.password.is_some() {
                render_index_page("".into(), file_info, true)
            } else {
                render_index_page("".into(), file_info, false)
            }
        }
        Err(msg) => render_index_page(
            format!("Secret found but could not be fetched: {}", msg),
            "".into(),
            false,
        ),
    }
}

fn render_index_page(error: String, info: String, password_required: bool) -> impl Responder {
    let index_page = IndexTemplate {
        json_config: Json(Config {
            error,
            info,
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
    render_index_page("".into(), "".into(), false)
}

#[post("/get_secret")]
async fn get_secret(db: web::Data<Database>, params: web::Json<Request>) -> impl Responder {
    let (key, password) = if let Json(Request::GetSecret { uuid, password }) = params {
        (uuid, password)
    } else {
        return HttpResponse::Ok().json(Response::Error("Invalid request!".to_string()));
    };

    let take = storage::take_entry_if(&db, &key.to_string(), |entry| match &entry.password {
        Some(hash) => bcrypt::verify(&password, hash).unwrap_or(false),
        None => true,
    });

    let entry = match take {
        Ok(Take::Taken(entry)) => entry,
        Ok(Take::Rejected) => {
            return HttpResponse::Ok().json(Response::Error("Invalid password!".to_string()))
        }
        Ok(Take::Missing) => {
            return HttpResponse::Ok().json(Response::Error(
                "Secret expired, not found or already viewed.".to_string(),
            ))
        }
        Err(msg) => return HttpResponse::Ok().json(Response::Error(format!("Error: {}", msg))),
    };

    let file_list = entry.file_list.keys().cloned().collect();

    HttpResponse::Ok().json(Response::Secret((entry.secret, file_list)))
}

#[post("/file/{uuid}/{file_name}")]
async fn upload_file(
    db: web::Data<Database>,
    path: web::Path<(Uuid, String)>,
    body: web::Bytes,
) -> impl Responder {
    let (uuid, file_name) = path.into_inner();

    match storage::set_file(&db, &uuid.to_string(), &file_name, &body) {
        Ok(true) => HttpResponse::Ok().json(Response::Ok),
        Ok(false) => HttpResponse::NotFound()
            .body("Unknown secret, undeclared file name or size mismatch."),
        Err(msg) => HttpResponse::InternalServerError().body(format!("Error: {}", msg)),
    }
}

// POST because fetching consumes the file (one-time read) — it must never be cached
#[post("/get_file/{uuid}/{file_name}")]
async fn download_file(
    db: web::Data<Database>,
    path: web::Path<(Uuid, String)>,
) -> impl Responder {
    let (uuid, file_name) = path.into_inner();

    match storage::take_file(&db, &uuid.to_string(), &file_name) {
        Ok(Some(bytes)) => HttpResponse::Ok()
            .content_type("application/octet-stream")
            .body(bytes),
        Ok(None) => HttpResponse::NotFound().body("File not found."),
        Err(msg) => HttpResponse::InternalServerError().body(format!("Error: {}", msg)),
    }
}

#[post("/new_secret")]
async fn new_secret(db: web::Data<Database>, params: web::Json<Request>) -> impl Responder {
    let (secret, password, lifetime, file_list) = if let Json(Request::CreateSecret {
        secret,
        password,
        lifetime,
        file_list,
    }) = params
    {
        let password = if let Some(password) = password {
            if let Ok(result) = bcrypt::hash(password, bcrypt::DEFAULT_COST) {
                Some(result)
            } else {
                return HttpResponse::InternalServerError().body("Error: Unable to hash password.");
            }
        } else {
            None
        };

        (secret, password, lifetime, file_list)
    } else {
        return HttpResponse::BadRequest().finish();
    };

    let lifetime = if DEFAULT_LIFETIMES.contains(&lifetime) {
        lifetime.to_seconds()
    } else {
        return HttpResponse::InternalServerError().body("Error: Invalid Lifetime");
    };

    // the client enforces these for UX; enforce them here for real
    if file_list.len() > *MAX_FILES as usize
        || file_list.values().sum::<u64>() > *MAX_FILES_SIZE
    {
        return HttpResponse::BadRequest().body("Error: File limits exceeded");
    }

    // ciphertext of the secret text: up to 4 bytes per char plus the GCM tag
    if secret.data.len() > *MAX_LENGTH as usize * 4 + 16 {
        return HttpResponse::BadRequest().body("Error: Secret too long");
    }

    let key = Uuid::new_v4();

    let entry = Entry {
        secret,
        password,
        file_list,
    };

    if let Err(msg) = storage::set_entry(&db, &key.to_string(), &entry, lifetime as u64) {
        return HttpResponse::InternalServerError().body(format!("Error: {}", msg));
    }

    HttpResponse::Ok().json(Response::Uuid(key))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("actix_web=info"))
        .init();

    let db = web::Data::new(storage::open(&DB_PATH).expect("Could not open database"));

    let sweep_db = db.clone();
    actix_web::rt::spawn(async move {
        let mut interval = actix_web::rt::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(e) = storage::sweep(&sweep_db) {
                eprintln!("Sweep failed: {}", e);
            }
        }
    });

    let adress = format!("0.0.0.0:{}", *PORT);

    println!("Listening on: {}", adress);

    HttpServer::new(move || {
        // raw upload bodies: declared file size + AES-GCM overhead, with slack
        let payload_limit = *MAX_FILES_SIZE as usize + 1024;

        // 'unsafe-inline' is needed for trunk's module loader, the config
        // script and leptos style attributes; the exfiltration channels
        // (connect, img, frames) stay locked to self regardless.
        let csp = "default-src 'self'; \
             script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; \
             connect-src 'self'; img-src 'self' data:; \
             object-src 'none'; frame-ancestors 'none'; \
             base-uri 'none'; form-action 'self'";

        let app = App::new()
            .app_data(db.clone())
            .app_data(web::PayloadConfig::new(payload_limit))
            .wrap(middleware::DefaultHeaders::new().add(("Content-Security-Policy", csp)))
            .wrap(Compress::default())
            .wrap(Logger::default())
            .service(index)
            .service(new_secret)
            .service(get_secret)
            .service(upload_file)
            .service(download_file)
            .service(index_uuid);

        app.service(Files::new("/pkg", "./client/dist/").prefer_utf8(true))
    })
    .bind(adress)?
    .run()
    .await
}
