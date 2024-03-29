use anyhow::{anyhow, Error};
use gloo_net::http::Request;
use if_chain::if_chain;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use shared::Lifetime;
use std::str::FromStr;
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use web_sys::{Document, HtmlButtonElement, HtmlElement, InputEvent, Url, Window};
use yew::{prelude::*, Context};

#[derive(Debug, Default)]
pub struct App {
    base_url: String,
    max_length: i32,
    lifetimes: Vec<Lifetime>,

    secret: String,
    uuid: Option<Uuid>,
    encrypt_key: String,
    password: String,
    password_required: bool,
    lifetime: Lifetime,

    error_msg: String,

    mode: Mode,
    button: NodeRef,
    result_field: NodeRef,
    copy_button: NodeRef,
    password_field: NodeRef,
}

#[derive(Debug, Default)]
enum Mode {
    #[default]
    New,
    Get,
    Error,
}

impl App {
    fn url(&self) -> String {
        if let Some(uuid) = &self.uuid {
            format!("{}/{}#{}", self.base_url, uuid, self.encrypt_key)
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

    fn length_display(&self) -> String {
        format!("{} / {}", self.secret.len(), self.max_length)
    }

    fn get_uuid_and_hash(key_len: i32) -> Option<Result<(Uuid, String), Error>> {
        if_chain! {
            if let Some(document) = App::get_document();
            if let Ok(url) = document.url();
            if let Ok(url) = Url::new(&url);

            let pathname: String = url.pathname();
            let hash: String = url.hash();

            if !pathname.is_empty();
            // pathname contains / as first char
            if let Ok(uuid) = Uuid::parse_str(&pathname[1..]);
            then {
                if hash.is_empty() {
                    Some(Err(anyhow!("Key missing, will not be able to encrypt secret!")))
                } else if (hash.len() - 1) != key_len as usize{
                    Some(Err(anyhow!("Invalid key length, will not be able to encrypt secret!")))
                } else {
                    // hash contains # as first char
                    let hash = hash[1..].to_string();
                    Some(Ok((uuid, hash)))
                }
            } else {
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
    UpdatePassword(String),
    UpdateLifetime(String),
}

pub enum AppError {
    FailedToFetchSecret,
    FailedToPostSecret,
    CreateSecretError,
    GetSecretError,
    DecryptError,
    ServerError(String),
    InvalidLifetime,
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        let mut config = if_chain! {
            if let Some(window) = App::get_window();
            if let Some(config) = window.get("config");
            if let Ok(config) = config.into_serde::<shared::Config>();
            then {
                config
            }else {
                shared::Config::default()
            }
        };

        // get the uuid and encryption key from the URL if present
        let result = App::get_uuid_and_hash(config.key_length);

        let (uuid, encrypt_key, mut mode) = match result {
            Some(Ok((uuid, hash))) => (Some(uuid), hash, Mode::Get),
            Some(Err(err)) => {
                config.error = err.to_string();
                (None, "".to_string(), Mode::Error)
            }
            None => {
                let mut rng = thread_rng();

                let key: String = (&mut rng)
                    .sample_iter(Alphanumeric)
                    .take(config.key_length as usize)
                    .map(char::from)
                    .collect();

                (None, key, Mode::New)
            }
        };

        if !config.error.is_empty() {
            mode = Mode::Error;
        };

        Self {
            password_required: config.password_required,
            base_url: config.base_url,
            uuid,
            encrypt_key,
            mode,
            error_msg: config.error,
            max_length: config.max_length,
            lifetimes: config.lifetimes,
            ..Default::default()
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, first_render: bool) {
        if first_render {
            if let Some(result_field) = self.result_field.cast::<HtmlElement>() {
                result_field.set_hidden(true);
            }
            if let Mode::Get = self.mode {
                if !self.password_required {
                    if let Some(field) = self.password_field.cast::<HtmlElement>() {
                        field.style().set_css_text("display: none");
                    }
                }
            }
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::UpdateSecret(_) => {}
            _ => self.error_msg = "".to_string(),
        }

        match msg {
            Msg::UpdateLifetime(value) => {
                if_chain! {
                    if let Some(unit) = value.chars().last();
                    let number = value.trim_end_matches(unit);
                    if let Ok(amount) = i32::from_str(number);
                    then{
                        match unit {
                            'd' => self.lifetime = Lifetime::Days(amount),
                            'h' => self.lifetime = Lifetime::Hours(amount),
                            'm' => self.lifetime = Lifetime::Minutes(amount),
                            _ => {}
                        }
                    }
                }
            }
            Msg::CreateSecret => {
                let mc = new_magic_crypt!(&self.encrypt_key, 256, "AES");

                let password = if self.password.is_empty() {
                    None
                } else {
                    Some(self.password.clone())
                };

                let body = shared::Request::CreateSecret {
                    encrypted_secret: mc.encrypt_str_to_base64(self.secret.clone()),
                    password,
                    lifetime: self.lifetime.clone(),
                };

                let post_request = Request::post("/new_secret")
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .expect("should not fail to serialize json")
                    .send();

                let link = ctx.link().clone();

                spawn_local(async move {
                    if let Ok(response) = post_request.await {
                        if let Ok(shared::Response::Uuid(uuid)) = response.json().await {
                            link.send_message(Msg::Uuid(uuid))
                        } else {
                            link.send_message(Msg::Error(AppError::CreateSecretError))
                        }
                    } else {
                        link.send_message(Msg::Error(AppError::FailedToPostSecret))
                    }
                });

                if let Some(button) = self.button.cast::<HtmlButtonElement>() {
                    self.password.truncate(0);
                    button.set_hidden(true);
                }
            }
            Msg::UpdateSecret(secret) => {
                if secret.len() <= self.max_length as usize {
                    self.secret = secret;
                }
            }
            Msg::Uuid(uuid) => {
                // ConsoleService::info(&format!("uuid: {:?}", uuid));
                let result_field = self
                    .result_field
                    .cast::<HtmlElement>()
                    .expect("Unexpected Element");
                result_field.set_hidden(false);

                self.uuid = Some(uuid);
            }
            Msg::Error(error) => match error {
                AppError::CreateSecretError => self.error_msg = "Could not create secret.".into(),
                AppError::GetSecretError => self.error_msg = "Could not get secret".into(),
                AppError::DecryptError => self.error_msg = "Could not decrypt secret.".into(),
                AppError::FailedToFetchSecret => self.error_msg = "Failed to fetch secret.".into(),
                AppError::FailedToPostSecret => self.error_msg = "Failed to post secret.".into(),
                AppError::InvalidLifetime => self.error_msg = "Invalid lifetime.".into(),
                AppError::ServerError(msg) => self.error_msg = msg,
            },
            Msg::GetSecret => {
                if let Some(uuid) = &self.uuid {
                    let body = shared::Request::GetSecret {
                        uuid: *uuid,
                        password: self.password.clone(),
                    };

                    let post_request = Request::post("/get_secret")
                        .header("Content-Type", "application/json")
                        .json(&body)
                        .expect("should not fail to serialize json")
                        .send();

                    let link = ctx.link().clone();
                    spawn_local(async move {
                        if let Ok(response) = post_request.await {
                            match response.json().await {
                                Ok(shared::Response::Secret(secret)) => {
                                    link.send_message(Msg::RevealSecret(secret));
                                }
                                Ok(shared::Response::Error(msg)) => {
                                    link.send_message(Msg::Error(AppError::ServerError(msg)));
                                }
                                Err(_msg) => {
                                    link.send_message(Msg::Error(AppError::GetSecretError));
                                }
                                Ok(shared::Response::Uuid(_)) => unreachable!(),
                            }
                        } else {
                            web_sys::console::log_1(&"Error Request".into());
                            link.send_message(Msg::Error(AppError::FailedToFetchSecret));
                        }
                    });
                }
            }
            Msg::RevealSecret(encrypted_secret) => {
                let mc = new_magic_crypt!(&self.encrypt_key, 256, "AES");
                if let Ok(secret) = mc.decrypt_base64_to_string(encrypted_secret) {
                    self.secret = secret;
                    if let Some(button) = self.button.cast::<HtmlElement>() {
                        button.set_hidden(true);
                    }
                    if let Some(field) = self.password_field.cast::<HtmlElement>() {
                        field.style().set_css_text("display: none");
                    }
                } else {
                    self.update(ctx, Msg::Error(AppError::DecryptError));
                };
            }
            Msg::CopyToClipboard => {
                if let Some(window) = App::get_window() {
                    let clipboard = window
                        .navigator()
                        .clipboard()
                        .expect("Could not access clipboard");

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
            Msg::UpdatePassword(password) => {
                self.password = password;
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let update_secret = ctx.link().callback(|e: InputEvent| {
            Msg::UpdateSecret(
                e.target_dyn_into::<web_sys::HtmlTextAreaElement>()
                    .expect("Unexpected Element")
                    .value(),
            )
        });
        let create_secret = ctx.link().callback(|_| Msg::CreateSecret);
        let show_secret = ctx.link().callback(|_| Msg::GetSecret);
        let copy_to_clipboard = ctx.link().callback(|_| Msg::CopyToClipboard);
        let update_password = ctx.link().callback(|e: InputEvent| {
            Msg::UpdatePassword(
                e.target_dyn_into::<web_sys::HtmlInputElement>()
                    .expect("Unexpected Element")
                    .value(),
            )
        });

        let update_lifetime = ctx.link().callback(|e: Event| {
            Msg::UpdateLifetime(
                e.target_dyn_into::<web_sys::HtmlSelectElement>()
                    .expect("Unexpected Element")
                    .value(),
            )
        });

        match self.mode {
            Mode::Error => html! {
                <div class="c">
                    <h1>{ "Error" }</h1>
                    <p>{ &self.error_msg }</p>
                </div>
            },
            Mode::Get => html! {
                <div class="c">
                    <h1>{ "View secret" }</h1>
                    <h5>{ "This can only be done ONCE!" }</h5>
                    <br/>
                    <p>{ &self.error_msg }</p>
                    <textarea style="resize: none;" class="card w-100" id="secret" name="secret" rows="10" cols="50" value={self.secret.to_string()}></textarea>
                    <hr/>
                    <div class="row" style="border-spacing:0 0">
                        <div class="3 col" style="padding-right: 1em" ref={self.password_field.clone()}>
                            <input oninput={update_password} value={self.password.to_string()} class="card" type="password" name="password" placeholder="Password required" />
                        </div>
                        <div class="col">
                            <button class="btn primary" ref={self.button.clone()} onclick={show_secret}>{ "Reveal" }</button>
                        </div>
                    </div>
                </div>
            },
            Mode::New => html! {
                <div class="c">
                    <h1>{ "Create new secret" }</h1>
                    <p>{ &self.error_msg }</p>
                    <textarea style="resize: none;" maxlength={self.max_length.to_string()} class="card w-100" id="secret" name="secret" rows="10" cols="50" oninput={update_secret} value={self.secret.to_string()}></textarea>
                    <div class="row" style="border-spacing:0 0">
                        <input oninput={update_password} value={self.password.to_string()} class="card" type="password" name="password" placeholder="Optional password" />
                        <label style="margin-left: 1em; color: #777">{ "Lifetime:" }</label>
                        <select onchange={update_lifetime} style="margin-left: 1em" class="card w-10">
                            { for self.lifetimes.iter().map(|lifetime|
                                html! {<option value={lifetime.to_string()} selected={self.lifetime == *lifetime}> { lifetime.long_string() }</option>})
                            }
                        </select>
                        <p class="3 col" style="text-align: right; color: #aaa">{ &self.length_display() }</p>
                    </div>
                    <hr/>
                    <div ref={self.result_field.clone()}>
                        <div class="row" style="border-spacing:0 0">
                            <div class="10 col" style="padding-right: 1em">
                                <pre>{ &self.url() }</pre>
                            </div>
                            <div class="3 col">
                                <button ref={self.copy_button.clone()} onclick={copy_to_clipboard} class="card btn" style="vertical-align: text-bottom; width: 100%">{ "Copy to Clipboard." }</button>
                            </div>
                        </div>
                    </div>
                    <button class="btn primary" ref={self.button.clone()} onclick={create_secret}>{ "Create" }</button>
                    <br/>
                    <br/>
                </div>
            },
        }
    }
}
