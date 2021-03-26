use anyhow::Error;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use web_sys::{Document, HtmlButtonElement, HtmlElement, Url};
use yew::{
    format::{Json, Nothing},
    prelude::*,
    services::{
        fetch::{FetchTask, Request, Response},
        FetchService,
    },
};

pub struct App {
    link: ComponentLink<Self>,
    secret: String,
    tasks: Vec<FetchTask>,
    base_url: String,
    uuid: Option<String>,
    encrypt_key: String,
    mode: Mode,
    error_msg: Option<String>,
    button: NodeRef,
    result_field: NodeRef,
}

enum Mode {
    New,
    Get,
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

    fn get_document() -> Option<Document> {
        let window = web_sys::window()?;
        window.document()
    }

    // this is madness...
    fn get_uuid_and_hash() -> Option<(String, String)> {
        if let Ok(url) = App::get_document()?.url() {
            if let Ok(url) = Url::new(&url) {
                let pathname: String = url.pathname();
                let hash: String = url.hash();

                if !pathname.is_empty() && !hash.is_empty() {
                    Some((pathname, hash))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateSecretResponse {
    pub uuid: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateSecretRequest {
    pub secret: String,
}

pub enum Msg {
    CreateSecret,
    UpdateSecret(String),
    GetSecret,
    RevealSecret(String),
    Uuid(String),
    Error(AppError),
}

pub enum AppError {
    CreateSecretError,
    GetSecretError,
    DecryptError,
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        // get the uuid and encryption key from the URL if present
        let (uuid, encrypt_key, mode) = if let Some((uuid, hash)) = App::get_uuid_and_hash() {
            // trim the leading / and #
            (
                Some((&uuid[1..]).to_string()),
                (&hash[1..]).to_string(),
                Mode::Get,
            )
        } else {
            let mut rng = thread_rng();

            let key: String = (&mut rng)
                .sample_iter(Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();

            (None, key, Mode::New)
        };

        Self {
            link,
            secret: "".to_string(),
            tasks: vec![],
            base_url: "http://localhost:8080".to_string(),
            uuid,
            encrypt_key,
            mode,
            error_msg: None,
            button: NodeRef::default(),
            result_field: NodeRef::default(),
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

                let body = CreateSecretRequest {
                    secret: mc.encrypt_str_to_base64(self.secret.clone()),
                };

                let post_request = Request::post("/new_secret")
                    .header("Content-Type", "application/json")
                    .body(Json(&body))
                    .unwrap();

                let res_cb = self.link.callback(
                    |response: Response<Json<Result<CreateSecretResponse, Error>>>| {
                        if let (_meta, Json(Ok(res))) = response.into_parts() {
                            Msg::Uuid(res.uuid)
                        } else {
                            Msg::Error(AppError::CreateSecretError)
                        }
                    },
                );

                let task = FetchService::fetch(post_request, res_cb).unwrap();

                let button = self.button.cast::<HtmlButtonElement>().unwrap();
                button.set_hidden(true);

                self.tasks.push(task);
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
            },
            Msg::GetSecret => {
                if let Some(uuid) = &self.uuid {
                    let get_request = Request::get(format!("/get_secret/{}", uuid))
                        .header("Content-Type", "application/json")
                        .body(Nothing)
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

                    let task = FetchService::fetch(get_request, request_callback).unwrap();

                    self.tasks.push(task);
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

        match self.mode {
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
                    <br/>
                    <p>{ &self.show_error() }</p>
                    <form action="/new_secret" method="post">
                    <textarea class="card w-100" id="secret" name="secret" rows="4" cols="50" oninput=update_secret value=&self.secret></textarea>
                    </form>
                    <hr/>
                    <pre ref=self.result_field.clone() >{ &self.url() }</pre>
                    <button class="btn primary" ref=self.button.clone() onclick=create_secret>{ "Create" }</button>
                    <br/>
                    <br/>
                </div>
            },
        }
    }
}
