use anyhow::Error;
use if_chain::if_chain;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use web_sys::{Document, HtmlButtonElement, HtmlElement, Url, Window};
use yew::{
    format::Json,
    prelude::*,
    services::{
        fetch::{FetchTask, Request, Response},
        ConsoleService, FetchService,
    },
};

pub struct App {
    link: ComponentLink<Self>,
    base_url: String,

    secret: String,
    uuid: Option<Uuid>,
    encrypt_key: String,

    error_msg: Option<String>,

    mode: Mode,
    tasks: Vec<FetchTask>,

    button: NodeRef,
    result_field: NodeRef,
    copy_button: NodeRef,
}

enum Mode {
    New,
    Get,
    Error,
}

impl App {
    fn url(&self) -> String {
        if let Some(uuid) = &self.uuid {
            format!("{}/{}#{}", self.base_url, uuid, self.encrypt_key)
        } else {
            format!("")
        }
    }

    fn show_error(&self) -> String {
        if let Some(msg) = &self.error_msg {
            msg.to_owned()
        } else {
            "".to_string()
        }
    }

    fn get_window() -> Option<Window> {
        web_sys::window()
    }

    fn get_document() -> Option<Document> {
        App::get_window()?.document()
    }

    fn get_uuid_and_hash() -> Option<(Uuid, String)> {
        if_chain! {
            if let Ok(url) = App::get_document()?.url();
            if let Ok(url) = Url::new(&url);
            let pathname: String = url.pathname();
            let hash: String = url.hash();
            if !pathname.is_empty() && !hash.is_empty();
            // pathname contains / as first char
            if let Ok(uuid) = Uuid::parse_str(&pathname[1..]);
            then {
                // hash contains # as first char
                Some((uuid, hash[1..].to_string()))
            }else {
                None
            }
        }
    }
}

pub enum Msg {
    CreateSecret,
    GetSecret,
    UpdateSecret(String),
    RevealSecret(String),
    Uuid(Uuid),
    Error(AppError),
    CopyToClipboard,
}

pub enum AppError {
    FailedToFetchSecret,
    FailedToPostSecret,
    CreateSecretError,
    GetSecretError,
    DecryptError,
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    error: Option<String>,
    base_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            error: None,
            base_url: "".to_string(),
        }
    }
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        // get the uuid and encryption key from the URL if present
        let (uuid, encrypt_key, mut mode) = if let Some((uuid, hash)) = App::get_uuid_and_hash() {
            (Some(uuid), hash, Mode::Get)
        } else {
            let mut rng = thread_rng();

            let key: String = (&mut rng)
                .sample_iter(Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();

            (None, key, Mode::New)
        };

        let config = if_chain! {
            if let Some(window) = App::get_window();
            if let Some(config) = window.get("config");
            if let Ok(config) = config.into_serde::<Config>();
            then {
                config
            }else {
                Config::default()
            }
        };

        if config.error.is_some() {
            mode = Mode::Error;
        };

        Self {
            link,
            secret: "".to_string(),
            tasks: vec![],
            base_url: config.base_url,
            uuid,
            encrypt_key,
            mode,
            error_msg: config.error,
            button: NodeRef::default(),
            result_field: NodeRef::default(),
            copy_button: NodeRef::default(),
        }
    }

    fn rendered(&mut self, first_render: bool) {
        if first_render {
            if let Some(result_field) = self.result_field.cast::<HtmlElement>() {
                result_field.set_hidden(true);
            }
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::CreateSecret => {
                let mc = new_magic_crypt!(&self.encrypt_key, 256, "AES");

                let body = shared::Request::CreateSecret {
                    encrypted_secret: mc.encrypt_str_to_base64(self.secret.clone()),
                    password: None,
                };

                let post_request = Request::post("/new_secret")
                    .header("Content-Type", "application/json")
                    .body(Json(&body))
                    .unwrap();

                let res_cb = self.link.callback(
                    |response: Response<Json<Result<shared::Response, Error>>>| {
                        if let (_meta, Json(Ok(shared::Response::Uuid(uuid)))) =
                            response.into_parts()
                        {
                            Msg::Uuid(uuid)
                        } else {
                            Msg::Error(AppError::CreateSecretError)
                        }
                    },
                );

                let task = FetchService::fetch(post_request, res_cb);
                if let Ok(task) = task {
                    self.tasks.push(task);
                } else {
                    self.update(Msg::Error(AppError::FailedToPostSecret));
                }

                if let Some(button) = self.button.cast::<HtmlButtonElement>() {
                    button.set_hidden(true);
                }
            }
            Msg::UpdateSecret(secret) => {
                self.secret = secret;
            }
            Msg::Uuid(uuid) => {
                // ConsoleService::info(&format!("uuid: {:?}", uuid));
                let result_field = self.result_field.cast::<HtmlElement>().unwrap();
                result_field.set_hidden(false);

                self.uuid = Some(uuid);
            }
            Msg::Error(error) => match error {
                AppError::CreateSecretError => {
                    self.error_msg = Some("Could not create secret.".into())
                }
                AppError::GetSecretError => self.error_msg = Some("Could not get secret".into()),
                AppError::DecryptError => self.error_msg = Some("Could not decrypt secret.".into()),
                AppError::FailedToFetchSecret => {
                    self.error_msg = Some("Failed to fetch secret.".into())
                }
                AppError::FailedToPostSecret => {
                    self.error_msg = Some("Failed to post secret.".into())
                }
            },
            Msg::GetSecret => {
                if let Some(uuid) = &self.uuid {
                    let body = shared::Request::GetSecret { uuid: *uuid };

                    let post_request = Request::post("/get_secret")
                        .header("Content-Type", "application/json")
                        .body(Json(&body))
                        .unwrap();

                    let request_callback =
                        self.link
                            .callback(|response: Response<Result<String, Error>>| {
                                if let (_meta, Ok(body)) = response.into_parts() {
                                    Msg::RevealSecret(body)
                                } else {
                                    Msg::Error(AppError::GetSecretError)
                                }
                            });

                    let task = FetchService::fetch(post_request, request_callback);
                    if let Ok(task) = task {
                        self.tasks.push(task);
                    } else {
                        self.update(Msg::Error(AppError::FailedToFetchSecret));
                    }
                }
            }
            Msg::RevealSecret(encrypted_secret) => {
                let mc = new_magic_crypt!(&self.encrypt_key, 256, "AES");
                if let Ok(secret) = mc.decrypt_base64_to_string(encrypted_secret) {
                    self.secret = secret;
                    let button = self.button.cast::<HtmlElement>().unwrap();
                    button.set_hidden(true);
                } else {
                    self.update(Msg::Error(AppError::DecryptError));
                };
            }
            Msg::CopyToClipboard => {
                if let Some(window) = App::get_window() {
                    let clipboard = window.navigator().clipboard();

                    let promise = web_sys::Clipboard::write_text(&clipboard, &self.url());
                    let future = wasm_bindgen_futures::JsFuture::from(promise);

                    if let Some(button) = self.copy_button.cast::<HtmlElement>() {
                        spawn_local(async move {
                            if future.await.is_ok() {
                                button.set_inner_text("Success!");
                            } else {
                                button.set_inner_text("Failure! :(");
                            }
                        })
                    }
                }
            }
        }
        true
    }

    fn change(&mut self, _prop: Self::Properties) -> ShouldRender {
        false
    }

    fn view(&self) -> Html {
        let update_secret = self
            .link
            .callback(|e: InputData| Msg::UpdateSecret(e.value));
        let create_secret = self.link.callback(|_| Msg::CreateSecret);
        let show_secret = self.link.callback(|_| Msg::GetSecret);
        let copy_to_clipboard = self.link.callback(|_| Msg::CopyToClipboard);

        match self.mode {
            Mode::Error => html! {
                <div class="c">
                    <h1>{ "Error" }</h1>
                    <p>{ &self.show_error() }</p>
                </div>
            },
            Mode::Get => html! {
                <div class="c">
                    <h1>{ "View secret" }</h1>
                    <h4>{ "This can only be done ONCE!" }</h4>
                    <br/>
                    <p>{ &self.show_error() }</p>
                    <textarea class="card w-100" id="secret" name="secret" rows="4" cols="50" value=&self.secret></textarea>
                    <hr/>
                    <br/>
                    <button class="btn primary" ref=self.button.clone() onclick=show_secret>{ "Reveal" }</button>
                </div>
            },
            Mode::New => html! {
                <div class="c">
                    <h1>{ "Create new secret" }</h1>
                    <p>{ &self.show_error() }</p>
                    <form action="/new_secret" method="post">
                    // TODO: config for max size, check on client and server side
                    <textarea maxlength="10000" class="card w-100" id="secret" name="secret" rows="4" cols="50" oninput=update_secret value=&self.secret></textarea>
                    </form>
                    <hr/>
                    <div ref=self.result_field.clone()>
                        <div class="row">
                            <div class="10 col">
                                <pre>{ &self.url() }</pre>
                            </div>
                            <div class="3 col">
                                <button ref=self.copy_button.clone() onclick=copy_to_clipboard class="card btn" style="vertical-align: text-bottom; width: 100%">{ "Copy to Clipboard." }</button>
                            </div>
                        </div>
                    </div>
                    <button class="btn primary" ref=self.button.clone() onclick=create_secret>{ "Create" }</button>
                    <br/>
                    <br/>
                </div>
            },
        }
    }
}
