use std::collections::HashMap;
use std::fmt::Display;

use byte_unit::Byte;
use magic_crypt::{new_magic_crypt, MagicCrypt256, MagicCryptTrait};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use seed::{
    attrs, button, div, h1, h5, hr, input, label, option, p, pre, prelude::*, select, style,
    textarea, virtual_dom::Node, C, IF,
};
use seed::{nodes, window, JsFuture};
use serde::{Deserialize, Serialize};
use shared::{Config, Lifetime};
use std::str;
use uuid::Uuid;
use web_sys::{console, Clipboard, DragEvent, FileList};

#[derive(Default)]
struct SecretShare {
    config: Config,
    encrypt_key: Option<String>,
    decrypt_key: Option<String>,

    drop_zone_active: bool,
    files: HashMap<String, (u128, Vec<u8>)>,

    mc: Option<MagicCrypt256>,
    encryption_in_progress: Option<(u128, u128)>,

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

    fn file_names(&self) -> Vec<(String, String)> {
        self.files
            .iter()
            .map(|(file_name, _)| {
                if file_name.len() > 35 {
                    let abbrev_name = file_name[0..35].to_string();
                    let ext = file_name[(file_name.len() - 3)..].to_string();
                    (file_name.clone(), format!("{}…{}", abbrev_name, ext))
                } else {
                    (file_name.clone(), file_name.clone())
                }
            })
            .collect()
    }

    fn get_crypt(&self) -> &MagicCrypt256 {
        self.mc.as_ref().expect("no crypt set")
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
    DragEnter,
    DragOver,
    DragLeave,
    Drop(FileList),
    FileRead((String, u128, Vec<u8>)),
    RemoveFile(String),
    EncryptFiles(usize, usize),
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
    let url = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.url().ok())
        .and_then(|url| web_sys::Url::new(&url).ok());

    if let Some(url) = url {
        let pathname: String = url.pathname();
        let hash: String = url.hash();

        if !pathname.is_empty() {
            if let Ok(uuid) = Uuid::parse_str(&pathname[1..]) {
                let hash = if hash.is_empty() {
                    return Some(Err(SecretShareError::KeyMissing));
                } else if (hash.len() - 1) != key_len as usize {
                    return Some(Err(SecretShareError::InvalidKeyLength));
                } else {
                    // hash contains # as first char
                    hash[1..].to_string()
                };

                return Some(Ok((uuid, hash)));
            }
        }
    }

    None
}

fn init(_: Url, _: &mut impl Orders<Msg>) -> SecretShare {
    let config: Config = window()
        .get("config")
        .and_then(|obj| {
            // the new recommanded way has some problem with the u128
            // serde_wasm_bindgen::from_value(obj.into()).ok()
            obj.into_serde::<shared::Config>().ok()
        })
        .unwrap_or_default();

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
                        .collect::<String>(),
                );
            }
        }
    }

    let mc = if let Some(key) = encrypt_key.clone() {
        Some(new_magic_crypt!(key, 256, "AES"))
    } else {
        decrypt_key
            .clone()
            .map(|key| new_magic_crypt!(key, 256, "AES"))
    };

    SecretShare {
        config,
        encrypt_key,
        error,
        decrypt_key,
        uuid,
        mc,
        clipboard_button_text: "Copy to Clipboard".into(),
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
    model.error = None;
    match msg {
        Msg::LifetimeChanged(lifetime) => {
            model.lifetime = lifetime.parse().expect("Invalid Lifetime")
        }
        Msg::SecretChanged(secret) => model.secret = Some(secret),
        Msg::PasswordChanged(password) => model.password = password,
        Msg::NewSecret => {
            let encrypted_secret = model.get_crypt().encrypt_str_to_base64(model.get_secret());

            let password = if model.password.is_empty() {
                None
            } else {
                Some(model.password.clone())
            };

            let file_list =
                model
                    .files
                    .iter()
                    .fold(HashMap::new(), |mut list, (filename, (size, _))| {
                        list.insert(model.get_crypt().encrypt_str_to_base64(filename), *size);
                        list
                    });

            let request = shared::Request::CreateSecret {
                encrypted_secret,
                password,
                lifetime: model.lifetime,
                file_list,
            };

            orders.perform_cmd(async move {
                Msg::Response(send_request(&request, "/new_secret").await)
            });
        }
        Msg::GetSecret => {
            let request = shared::Request::GetSecret {
                uuid: model.uuid.expect("no uuid set"),
                password: model.password.clone(),
            };
            orders.perform_cmd(async move {
                Msg::Response(send_request(&request, "/get_secret").await)
            });
        }
        Msg::Response(result) => match result {
            Ok(response) => match response {
                shared::Response::Uuid(uuid) => {
                    model.uuid = Some(uuid);
                    if !model.files.is_empty() {
                        // encrypt and send files after we created the secret
                        orders.perform_cmd(async { Msg::EncryptFiles(0, 0) });
                    }
                }
                shared::Response::Secret(encrypted_secret) => {
                    match model.get_crypt().decrypt_base64_to_string(encrypted_secret) {
                        Ok(secret) => model.secret = Some(secret),
                        Err(e) => model.error = Some(e.to_string()),
                    }
                }
                shared::Response::Ok => (),
                shared::Response::Error(e) => model.error = Some(e),
            },
            Err(e) => {
                model.error = Some(format!("{:?}", e));
            }
        },
        Msg::CopyUrl => {
            let clipboard = window()
                .navigator()
                .clipboard()
                .expect("Could not access clipboard");

            let promise = Clipboard::write_text(&clipboard, &model.url());
            let future = JsFuture::from(promise);

            orders.perform_cmd(async move { Msg::CopyResult(future.await) });
        }
        Msg::CopyResult(result) => {
            if result.is_ok() {
                model.clipboard_button_text = "Success!".into();
            } else {
                model.clipboard_button_text = "Failure! :(".into();
            }
        }
        Msg::DragEnter => model.drop_zone_active = true,
        Msg::DragLeave => model.drop_zone_active = false,
        Msg::DragOver => (),
        Msg::Drop(file_list) => {
            // Note: `FileList` doesn't implement `Iterator`.
            let files = (0..file_list.length())
                .map(|index| file_list.get(index).expect("get file with given index"))
                .collect::<Vec<_>>();

            if files.len() + model.files.len() > model.config.max_files as usize {
                model.drop_zone_active = false;
                model.error = Some(format!("Only {} files allowed.", model.config.max_files));
                return;
            }

            let new_files_size = files.iter().fold(0, |acc, file| acc + file.size() as u128);
            let current_files_size = model.files.iter().fold(0, |acc, (_, (size, _))| acc + size);
            if new_files_size + current_files_size > model.config.max_files_size {
                model.drop_zone_active = false;
                let max_size =
                    Byte::from_bytes(model.config.max_files_size).get_appropriate_unit(true);
                model.error = Some(format!("Max acc. file size of {} exceeded.", max_size));
                return;
            }
            // Read files (async).
            for file in files {
                orders.perform_cmd(async move {
                    let content =
                        // Convert `promise` to `Future`.
                        JsFuture::from(file.text())
                            .await
                            .expect("read file")
                            .as_string()
                            .expect("cast file text to String")
                            .as_bytes()
                            .to_vec();
                    Msg::FileRead((file.name(), file.size() as u128, content))
                });
            }
        }
        Msg::FileRead((file_name, size, content)) => {
            model.files.insert(file_name, (size, content));
            model.drop_zone_active = false;
        }
        Msg::RemoveFile(file_name) => {
            model.files.remove(&file_name);
        }
        // Web Workers are a shit show right now, so I encrypt the files in little chunks to not
        // block the main thread for too long, nice side effect, I can easily display a fancy progress bar
        Msg::EncryptFiles(current_index, position) => {
            if model.encryption_in_progress.is_none() {
                let sum_data = model
                    .files
                    .iter()
                    .fold(0, |acc, (_, (_, data))| acc + data.len());
                model.encryption_in_progress = Some((0, sum_data as u128));
            };

            for (index, (file_name, (_size, data))) in model.files.iter().enumerate() {
                if index == current_index {
                    let mut next_index = current_index;
                    let next_chunk;

                    let offset = position * model.config.chunk_size;
                    let encrypted_chunk = if offset + model.config.chunk_size > data.len() {
                        next_index += 1;
                        next_chunk = 0;

                        // I'm not smart enough to figure out how I can use model.get_crypt() here...
                        model
                            .mc
                            .as_ref()
                            .expect("no crypt set")
                            .encrypt_bytes_to_bytes(&data[offset..])
                    } else {
                        next_chunk = position + 1;
                        model
                            .mc
                            .as_ref()
                            .expect("no crypt set")
                            .encrypt_bytes_to_bytes(
                                &data[offset..(offset + model.config.chunk_size)],
                            )
                    };

                    // save to unwrap, because its getting set in the if statement before the loop
                    let cur_progress = model.encryption_in_progress.unwrap();
                    model.encryption_in_progress = Some((
                        cur_progress.0 + encrypted_chunk.len() as u128,
                        cur_progress.1,
                    ));

                    let uuid = model.uuid.expect("no Uuid");
                    let file_name = model.get_crypt().encrypt_str_to_base64(file_name);
                    let request = shared::Request::SendFileChunk {
                        uuid,
                        file_name,
                        chunk_index: position,
                        chunk: encrypted_chunk,
                    };

                    orders.perform_cmd(async move {
                        Msg::Response(send_request(&request, "/file_chunk").await)
                    });
                    orders.after_next_render(move |_| Msg::EncryptFiles(next_index, next_chunk));
                }
            }

            if current_index > model.files.len() - 1 {
                model.encryption_in_progress = None;
                console::log_1(&"Done".into());
            }
        }
    }
}

macro_rules! stop_and_prevent {
    { $event:expr } => {
        {
            $event.stop_propagation();
            $event.prevent_default();
        }
     };
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
                textarea![C!["card w-100"], style![St::Resize => "none"],
                    attrs![At::Id => "secret", At::Name => "secret", At::Rows => "10", At::Cols => "50", At::Value => model.get_secret(), At::ReadOnly => true]
                ]
                hr![],
                IF!(model.secret.is_none() =>
                    div![C!["row"], style![St::BorderSpacing => "0 0"],
                        IF!( model.config.password_required =>
                            div![C!["3 col"], style![St::PaddingRight => em(1)],
                                input![C!["card"],
                                    input_ev(Ev::Change, Msg::PasswordChanged),
                                    attrs![At::Value => model.password, At::Type => "password", At::Name => "password", At::Placeholder => "Password required"]
                                ],
                            ]
                        ),
                        div![C!["col"],
                            button![C!["btn primary"],
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
                div![C!["row"],
                    h1!["Create new secret"],
                    p![&model.error, " "], // invesible char to keep the element height the same if error is empty
                ],
                div![C!["row"],
                    textarea![C!["col 6 card w-100"], style![St::Resize => "none", St::MarginBottom => em(-1)],
                        attrs![At::MaxLength => model.config.max_length, At::Id => "secret", At::Name => "secret",  At::Rows => "10",  At::Cols => "50"],
                        input_ev(Ev::Input, Msg::SecretChanged)
                    ],
                    // the whole drop stuff is basically from here:
                    // https://github.com/seed-rs/seed/blob/4096a77a79e3a15fc12d2ea864e0e1d51a8f3638/examples/drop_zone/src/lib.rs
                    div![C![if model.drop_zone_active || !model.files.is_empty() { "col 6 card w-50" } else { "col 3 card w-50" }],
                            style![St::BorderStyle => "dashed", St::BorderRadius => px(20)
                            St::Transition => "width 0.25s ease-out"],
                        ev(Ev::DragEnter, |event| {
                            stop_and_prevent!(event);
                            Msg::DragEnter
                        }),
                        ev(Ev::DragOver, |event| {
                            let drag_event = event.dyn_into::<DragEvent>().expect("cannot cast given event into DragEvent");
                            stop_and_prevent!(drag_event);
                            drag_event.data_transfer().unwrap().set_drop_effect("copy");
                            Msg::DragOver
                        }),
                        ev(Ev::DragLeave, |event| {
                            stop_and_prevent!(event);
                            Msg::DragLeave
                        }),
                        ev(Ev::Drop, |event| {
                            let drag_event = event.dyn_into::<DragEvent>().expect("cannot cast given event into DragEvent");
                            stop_and_prevent!(drag_event);
                            let file_list = drag_event.data_transfer().unwrap().files().unwrap();
                            Msg::Drop(file_list)
                        }),
                        div![style![St::Float => "left"],
                            model.file_names().iter().map(|(name, abbr_name)|
                                div![style![St::Margin => "0.18em 0"],
                                    div![style![St::Float => "Left", St::Cursor => "pointer", St::PaddingRight => px(5)],
                                    {
                                        let file_name = name.clone();
                                        ev(Ev::Click, |_| Msg::RemoveFile(file_name))
                                    },
                                        "❌"
                                    ],
                                    abbr_name
                                ]
                            ).collect::<Vec<_>>()
                        ],
                    ]
                ],
                div![C!["row"],
                    p![C!["4 col"], style![St::TextAlign => St::Left, St::Color => "#aaa"],
                        format!("Text: {} / {}", model.get_secret().len(), model.config.max_length),
                    ],
                    p![C!["2 col"], style![St::TextAlign => if !model.files.is_empty() { "center".into() } else { St::Right }, St::Color => "#aaa"],
                        format!("Files: {} / {}", model.files.len(), model.config.max_files)
                    ],
                    IF!(!model.files.is_empty() =>
                        p![C!["3 col"], style![St::TextAlign => St::Right, St::Color => "#aaa"],
                            {let curr_size = Byte::from_bytes(model.files.iter().fold(0, |acc, (_, (x, _))| acc + *x as u128));
                            let max_size = Byte::from_bytes(model.config.max_files_size as u128).get_appropriate_unit(true);
                            format!("Max Size: {} / {}", curr_size.get_appropriate_unit(true), max_size)}
                        ]
                    )
                ],
                div![C!["row"],
                    hr![]
                ],
                div![C!["row"],
                    IF!(model.uuid.is_some() && model.encryption_in_progress.is_none() =>
                        // div![C!["row"],
                        nodes![
                            div![C!["10 col"], style![St::PaddingRight => em(1), St::TextAlign => "center"],
                                pre![model.url()]
                            ],
                            div![C!["3 col"],
                                button![C!["card btn"], style![St::VerticalAlign => St::from("text-bottom"), St::Width => percent(100)],
                                    input_ev(Ev::Click, |_| Msg::CopyUrl),
                                    model.clipboard_button_text.clone()
                                ]
                            ]
                        ]
                    ),
                    IF!(model.encryption_in_progress.is_some() =>
                        {
                            let (cur, over) = model.encryption_in_progress.unwrap();
                            let percentage = 100 * cur / over;
                            let background = format!("linear-gradient(90deg, #eee {}%, white 0)", percentage);
                            div![C!["card"], style![St::TextAlign => "center", St::Background => background],
                                format!("Encrypting and Sending Files: {}/{}", model.encryption_in_progress.unwrap().0, model.encryption_in_progress.unwrap().1)
                            ]
                        }
                    ),
                    IF!(model.uuid.is_none() && model.encryption_in_progress.is_none() =>
                        nodes![
                            input![C!["card"], attrs![At::Value => model.password, At::Type => "password", At::Name => "password", At::Placeholder => "Optional password"],
                                input_ev(Ev::Change, Msg::PasswordChanged)
                            ],
                            label![style![St::MarginLeft => em(1), St::Color => "#777"],
                                "Lifetime:"
                            ],
                            select![ C!["card w-10"], style![St::MarginLeft => em(1)],
                                input_ev(Ev::Change, Msg::LifetimeChanged),
                                model.config.lifetimes.iter().map(|lt|
                                    option![attrs![At::Value => lt.to_string(), At::Selected => (*lt == model.lifetime).as_at_value()], lt.long_string()]
                                ),
                            ],
                            button![C!["btn primary"], style!(St::Float => St::Right),
                                input_ev(Ev::Click, |_| Msg::NewSecret),
                                "Create"
                            ],
                        ]
                    )
                ]
            ]
        )
    ]]
}

#[wasm_bindgen(start)]
pub fn start() {
    App::start("secret_share", init, update, view);
}
