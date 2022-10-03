use std::fmt::Display;

use if_chain::if_chain;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use seed::nodes;
use seed::{
    attrs, button, div, h1, h5, hr, input, label, option, p, pre, prelude::*, select, style,
    textarea, virtual_dom::Node, C, IF,
};
use serde::{Deserialize, Serialize};
use shared::{Config, Lifetime};
use uuid::Uuid;

#[derive(Debug, Default)]
struct SecretShare {
    config: Config,
    encrypt_key: Option<String>,
    decrypt_key: Option<String>,

    clipboard_button_text: String,
    uuid: Option<Uuid>,
    error: Option<String>,
    password: String,
    lifetime: Lifetime,
    secret: Option<String>,
}

impl SecretShare {
    fn url(&self) -> String {
        format!(
            "{}/{}#{}",
            self.config.base_url,
            self.uuid.expect("No uuid set"),
            self.encrypt_key.as_ref().expect("No encrypt key set")
        )
    }

    fn get_secret(&self) -> String {
        if let Some(secret) = &self.secret {
            secret.clone()
        } else {
            "".to_string()
        }
    }
}

enum Msg {
    LifetimeChanged(String),
    SecretChanged(String),
    PasswordChanged(String),
    NewSecret,
    Response(fetch::Result<shared::Response>),
    GetSecret,
    CopyUrl,
    CopyResult(Result<JsValue, JsValue>),
}

enum SecretShareError {
    KeyMissing,
    InvalidKeyLength,
}

impl Display for SecretShareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyMissing => f.write_str("decrypt key missing from url"),
            Self::InvalidKeyLength => f.write_str("decrypt key has invalid length"),
        }
    }
}

fn get_uuid_and_hash(key_len: i32) -> Option<Result<(Uuid, String), SecretShareError>> {
    if_chain! {
        if let Some(document) = web_sys::window()?.document();
        if let Ok(url) = document.url();
        if let Ok(url) = web_sys::Url::new(&url);

        let pathname: String = url.pathname();
        let hash: String = url.hash();

        if !pathname.is_empty();
        // pathname contains / as first char
        if let Ok(uuid) = Uuid::parse_str(&pathname[1..]);
        then {
            if hash.is_empty() {
                Some(Err(SecretShareError::KeyMissing))
            } else if (hash.len() - 1) != key_len as usize{
                Some(Err(SecretShareError::InvalidKeyLength))
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

fn init(_: Url, _: &mut impl Orders<Msg>) -> SecretShare {
    let config = if_chain! {
        if let Some(window) = web_sys::window();
        if let Some(config) = window.get("config");
        if let Ok(config) = serde_wasm_bindgen::from_value(config.into());
        then {
            config
        }else {
            Config::default()
        }
    };

    let mut encrypt_key = None;
    let mut error = None;
    let mut decrypt_key = None;
    let mut uuid = None;

    // if the server is unabel to find the secret we bail out directly
    if !config.error.is_empty() {
        error = Some(config.error.clone());
    } else {
        match get_uuid_and_hash(config.key_length) {
            Some(result) => match result {
                Ok((url_uuid, key)) => {
                    decrypt_key = Some(key);
                    uuid = Some(url_uuid);
                }
                Err(e) => error = Some(e.to_string()),
            },
            None => {
                encrypt_key = Some(
                    (&mut thread_rng())
                        .sample_iter(Alphanumeric)
                        .take(config.key_length as usize)
                        .map(char::from)
                        .collect(),
                );
            }
        }
    }

    SecretShare {
        config,
        encrypt_key,
        error,
        decrypt_key,
        uuid,
        clipboard_button_text: "Copy to Clipboard.".into(),
        ..Default::default()
    }
}

async fn send_request<V, T>(variables: &V, url: &str) -> fetch::Result<T>
where
    V: Serialize,
    T: for<'de> Deserialize<'de> + 'static,
{
    Request::new(url)
        .method(Method::Post)
        .json(variables)?
        .fetch()
        .await?
        .check_status()?
        .json()
        .await
}

fn update(msg: Msg, model: &mut SecretShare, orders: &mut impl Orders<Msg>) {
    match msg {
        Msg::LifetimeChanged(lifetime) => {
            model.lifetime = lifetime.parse().expect("Invalid Lifetime")
        }
        Msg::SecretChanged(secret) => model.secret = Some(secret),
        Msg::PasswordChanged(password) => model.password = password,
        Msg::NewSecret => {
            let mc = new_magic_crypt!(
                &model.encrypt_key.as_ref().expect("No encrypt key set"),
                256,
                "AES"
            );

            let encrypted_secret = mc.encrypt_str_to_base64(model.get_secret());

            let password = if model.password.is_empty() {
                None
            } else {
                Some(model.password.clone())
            };

            let request = shared::Request::CreateSecret {
                encrypted_secret,
                password,
                lifetime: model.lifetime,
            };

            orders.perform_cmd(async move {
                Msg::Response(send_request(&request, "/new_secret").await)
            });
        }
        Msg::GetSecret => {
            let request = shared::Request::GetSecret {
                uuid: model.uuid.expect("uuid not set"),
                password: model.password.clone(),
            };
            orders.perform_cmd(async move {
                Msg::Response(send_request(&request, "/get_secret").await)
            });
        }
        Msg::Response(result) => match result {
            Ok(response) => match response {
                shared::Response::Uuid(uuid) => model.uuid = Some(uuid),
                shared::Response::Secret(encrypted_secret) => {
                    let mc = new_magic_crypt!(
                        &model.decrypt_key.as_ref().expect("No encrypt key set"),
                        256,
                        "AES"
                    );

                    match mc.decrypt_base64_to_string(encrypted_secret) {
                        Ok(secret) => model.secret = Some(secret),
                        Err(e) => model.error = Some(e.to_string()),
                    }
                }
                shared::Response::Error(e) => model.error = Some(e),
            },
            Err(e) => {
                model.error = Some(format!("{:?}", e));
            }
        },
        Msg::CopyUrl => {
            if let Some(window) = web_sys::window() {
                let clipboard = window
                    .navigator()
                    .clipboard()
                    .expect("Could not access clipboard");

                let promise = web_sys::Clipboard::write_text(&clipboard, &model.url());
                let future = wasm_bindgen_futures::JsFuture::from(promise);

                orders.perform_cmd(async move { Msg::CopyResult(future.await) });
            }
        }
        Msg::CopyResult(result) => {
            if result.is_ok() {
                model.clipboard_button_text = "Success!".into();
            } else {
                model.clipboard_button_text = "Failure! :(".into();
            }
        }
    }
}

fn view(model: &SecretShare) -> Vec<Node<Msg>> {
    nodes![div![
        C!["c"],
        // always display the errors
        IF!(model.decrypt_key.is_none() && model.encrypt_key.is_none() => p![&model.error] ),
        // secret viewing
        IF!(model.decrypt_key.is_some() =>
            nodes![
                h1!["View secret"],
                h5!["This can only be done ONCE!"]
                p![&model.error],
                textarea![
                    C!["card w-100"],
                    style![St::Resize => "none"],
                    attrs![At::Id => "secret", At::Name => "secret", At::Rows => "10", At::Cols => "50", At::Value => model.get_secret(), At::ReadOnly => true],
                ]
                hr![],
                IF!(model.secret.is_none() =>
                    div![
                        C!["row"],
                        style![St::BorderSpacing => "0 0"],
                        IF!( model.config.password_required =>
                            div![
                                C!["3 col"], style![St::PaddingRight => em(1)],
                                input![
                                    input_ev(Ev::Change, Msg::PasswordChanged),
                                    C!["card"],
                                    attrs![At::Value => model.password, At::Type => "password", At::Name => "password", At::Placeholder => "Password required"]
                                ],
                            ]
                        ),
                        div![C!["col"],
                            button![
                                C!["btn primary"],
                                input_ev(Ev::Click, |_| Msg::GetSecret),
                                "Reveal"
                            ]
                        ]
                    ]
                )
            ]
        ),
        // secret creation
        IF!(model.encrypt_key.is_some() =>
            nodes![
                h1!["Create new secret"],
                p![&model.error],
                textarea![
                    input_ev(Ev::Input, Msg::SecretChanged),
                    C!["card w-100"],
                    style![St::Resize => "none"],
                    attrs![At::MaxLength => model.config.max_length, At::Id => "secret", At::Name => "secret",  At::Rows => "10",  At::Cols => "50"]
                ],
                div![
                    C!["row"],
                    style![St::BorderSpacing => "0 0"],
                    input![
                        input_ev(Ev::Change, Msg::PasswordChanged),
                        C!["card"],
                        attrs![At::Value => model.password, At::Type => "password", At::Name => "password", At::Placeholder => "Optional password"]
                    ],
                    label![
                        style![St::MarginLeft => em(1), St::Color => "#777"],
                        "Lifetime:"
                    ],
                    select![
                        input_ev(Ev::Change, Msg::LifetimeChanged),
                        C!["card w-10"],
                        style![St::MarginLeft => em(1)],
                        model.config.lifetimes.iter().map(|lt|
                            option![attrs! {At::Value => lt.to_string(), At::Selected => (*lt == model.lifetime).as_at_value()}, lt.long_string()]
                        ),
                    ],
                    p![
                        C!["3 col"],
                        style![St::TextAlign => St::Right, St::Color => "#aaa"],
                        format!("{} / {}", model.get_secret().len(), model.config.max_length)
                    ]
                ],
                hr![],
                div![
                    IF!(model.uuid.is_some() =>
                        div![
                            C!["row"],
                            style![St::BorderSpacing => "0 0"],
                            div![
                                C!["10 col"],
                                style![St::PaddingRight => em(1)],
                                pre![model.url()]
                            ],
                            div![
                                C!["3 col"],
                                button![
                                    C!["card btn"],
                                    input_ev(Ev::Click, |_| Msg::CopyUrl),
                                    style![St::VerticalAlign => St::from("text-bottom"), St::Width => percent(100)],
                                    model.clipboard_button_text.clone()
                                ]
                            ]
                        ]
                    )
                ],
                IF!(model.uuid.is_none() =>
                    button![
                        input_ev(Ev::Click, |_| Msg::NewSecret),
                        C!["btn primary"],
                        "Create"
                    ]
                )
            ]
        )
    ]]
}

#[wasm_bindgen(start)]
pub fn start() {
    App::start("secret_share", init, update, view);
}
