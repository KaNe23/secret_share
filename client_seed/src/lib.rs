mod secret_share;

use std::collections::HashMap;
use std::fmt::Display;

use byte_unit::Byte;
use js_sys::Uint8Array;
use rand::distr::Alphanumeric;
use rand::{rng, RngExt};
use secret_share::SecretShare;
use seed::{a, nodes, window, JsFuture};
use seed::{
    attrs, button, div, h1, h5, hr, input, label, option, p, pre, prelude::*, select, style,
    textarea, virtual_dom::Node, C, IF,
};
use serde::{Deserialize, Serialize};
use shared::{Config, EncryptedData};
use std::str;
use uuid::Uuid;
use web_sys::{Clipboard, DragEvent, FileList, HtmlInputElement};

enum Msg {
    LifetimeChanged(String),
    SecretChanged(String),
    PasswordChanged(String),
    NewSecret,
    Response(Result<shared::Response, String>),
    GetSecret,
    SecretDecrypted(Result<String, String>, Vec<String>),
    CopyUrl,
    CopyResult(Result<JsValue, JsValue>),
    DragEnter,
    DragOver,
    DragLeave,
    Drop(FileList),
    FileRead(Result<(String, String, u64, Vec<u8>), String>),
    RemoveFile(String),
    TransferNext,
    Uploaded(Result<(), String>),
    Downloaded(Result<(String, Vec<u8>), String>),
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

type UuidHashResult = Option<Result<(Uuid, String), SecretShareError>>;

fn get_uuid_and_hash() -> UuidHashResult {
    let key_len = 32;
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
                    hash.trim_start_matches('#').to_string()
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
            serde_wasm_bindgen::from_value(obj.into()).ok()
        })
        .unwrap_or_default();

    let mut encrypt_key = None;
    let mut decrypt_key = None;
    let mut error = None;
    let mut uuid = None;

    // if the server is unabel to find the secret we bail out directly
    if !config.error.is_empty() {
        error = Some(config.error.clone());
    } else {
        match get_uuid_and_hash() {
            Some(result) => match result {
                Ok((url_uuid, key)) => {
                    decrypt_key = Some(key);
                    uuid = Some(url_uuid);
                }
                Err(e) => error = Some(e.to_string()),
            },
            None => {
                encrypt_key = Some(
                    (&mut rng())
                        .sample_iter(Alphanumeric)
                        .take(32) // AES-256 needs a 32 byte key
                        .map(char::from)
                        .collect::<String>(),
                );
            }
        }
    }

    SecretShare {
        config,
        encrypt_key,
        decrypt_key,
        error,
        uuid,
        clipboard_button_text: "Copy to Clipboard".into(),
        ..Default::default()
    }
}

async fn send_request<V, T>(variables: &V, url: &str) -> Result<T, String>
where
    V: Serialize,
    T: for<'de> Deserialize<'de> + 'static,
{
    let response = gloo_net::http::Request::post(url)
        .json(variables)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !response.ok() {
        return Err(format!("HTTP status {}", response.status()));
    }
    response.json().await.map_err(|e| e.to_string())
}

async fn upload_file(
    key: String,
    uuid: Uuid,
    encrypted_name: String,
    bytes: Vec<u8>,
) -> Result<(), String> {
    let blob = secret_share::encrypt_blob(&key, &bytes).await?;
    let body = Uint8Array::from(blob.as_slice());
    let response = gloo_net::http::Request::post(&format!("/file/{}/{}", uuid, encrypted_name))
        .body(body)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if response.ok() {
        Ok(())
    } else {
        Err(format!("Upload failed: HTTP {}", response.status()))
    }
}

async fn download_file(
    key: String,
    uuid: Uuid,
    encrypted_name: String,
) -> Result<(String, Vec<u8>), String> {
    let response =
        gloo_net::http::Request::post(&format!("/get_file/{}/{}", uuid, encrypted_name))
            .send()
            .await
            .map_err(|e| e.to_string())?;
    if !response.ok() {
        return Err(format!("Download failed: HTTP {}", response.status()));
    }
    let blob = response.binary().await.map_err(|e| e.to_string())?;
    let bytes = secret_share::decrypt_blob(&key, &blob).await?;

    let encrypted: EncryptedData = encrypted_name
        .parse()
        .map_err(|_| "Invalid file name".to_string())?;
    let name_bytes = secret_share::decrypt_data(&key, &encrypted).await?;
    let file_name = String::from_utf8(name_bytes).map_err(|e| e.to_string())?;

    Ok((file_name, bytes))
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
            let key = model.key();
            let text = model.get_secret();

            let password = if model.password.is_empty() {
                None
            } else {
                Some(model.password.clone())
            };

            let lifetime = model.lifetime;
            let file_list: HashMap<String, u64> = model
                .files
                .values()
                .map(|(encrypted_file_name, size, _)| (encrypted_file_name.clone(), *size))
                .collect();

            orders.perform_cmd(async move {
                let secret = match secret_share::encrypt_data(&key, text.as_bytes()).await {
                    Ok(secret) => secret,
                    Err(e) => return Msg::Response(Err(e)),
                };
                let request = shared::Request::CreateSecret {
                    secret,
                    password,
                    lifetime,
                    file_list,
                };
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
                        // encrypt and upload the files now that the secret exists
                        model.requests = model
                            .files
                            .values()
                            .map(|(encrypted_name, _, bytes)| {
                                (encrypted_name.clone(), bytes.clone())
                            })
                            .collect();
                        model.cryption_in_progress = Some((0, model.requests.len() as u64));
                        orders.send_msg(Msg::TransferNext);
                    }
                }
                shared::Response::Secret((secret, file_list)) => {
                    let key = model.key();
                    orders.perform_cmd(async move {
                        let text = match secret_share::decrypt_data(&key, &secret).await {
                            Ok(bytes) => String::from_utf8(bytes).map_err(|e| e.to_string()),
                            Err(e) => Err(e),
                        };
                        Msg::SecretDecrypted(text, file_list)
                    });
                }
                shared::Response::Ok => {}
                shared::Response::Error(e) => model.error = Some(e),
            },
            Err(e) => {
                model.error = Some(e);
            }
        },
        Msg::SecretDecrypted(result, file_list) => match result {
            Ok(text) => {
                model.secret = Some(text);
                if !file_list.is_empty() {
                    model.requests = file_list.into_iter().map(|name| (name, vec![])).collect();
                    model.cryption_in_progress = Some((0, model.requests.len() as u64));
                    orders.send_msg(Msg::TransferNext);
                }
            }
            Err(e) => model.error = Some(e),
        },
        Msg::TransferNext => {
            if let Some((encrypted_name, bytes)) = model.requests.pop() {
                let key = model.key();
                let uuid = model.uuid.expect("no uuid set");
                if model.decrypt_key.is_some() {
                    orders.perform_cmd(async move {
                        Msg::Downloaded(download_file(key, uuid, encrypted_name).await)
                    });
                } else {
                    orders.perform_cmd(async move {
                        Msg::Uploaded(upload_file(key, uuid, encrypted_name, bytes).await)
                    });
                }
            } else {
                model.cryption_in_progress = None;
            }
        }
        Msg::Uploaded(result) => match result {
            Ok(()) => {
                if let Some((cur, over)) = model.cryption_in_progress {
                    model.cryption_in_progress = Some((cur + 1, over));
                }
                orders.send_msg(Msg::TransferNext);
            }
            Err(e) => {
                model.cryption_in_progress = None;
                model.error = Some(e);
            }
        },
        Msg::Downloaded(result) => match result {
            Ok((file_name, bytes)) => {
                let file = gloo_file::File::new(&file_name, bytes.as_slice());
                let blob = gloo_file::Blob::from(file);
                let download_url =
                    web_sys::Url::create_object_url_with_blob(&blob.into()).unwrap();
                model.blob_list.push((download_url, file_name));

                if let Some((cur, over)) = model.cryption_in_progress {
                    model.cryption_in_progress = Some((cur + 1, over));
                }
                orders.send_msg(Msg::TransferNext);
            }
            Err(e) => {
                model.cryption_in_progress = None;
                model.error = Some(e);
            }
        },
        Msg::CopyUrl => {
            let clipboard = window().navigator().clipboard();

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

            let new_files_size = files.iter().fold(0, |acc, file| acc + file.size() as u64);
            let current_files_size = model
                .files
                .iter()
                .fold(0, |acc, (_, (_, size, _))| acc + size);
            if new_files_size + current_files_size > model.config.max_files_size {
                model.drop_zone_active = false;
                let max_size = Byte::from_u64(model.config.max_files_size)
                    .get_appropriate_unit(byte_unit::UnitType::Binary);
                model.error = Some(format!("Max acc. file size of {} exceeded.", max_size));
                return;
            }
            // Read files and encrypt their names; content is encrypted at upload time
            for file in files {
                let key = model.key();
                orders.perform_cmd(async move {
                    let name = file.name();
                    let size = file.size() as u64;
                    let result = async {
                        let bytes = gloo_file::futures::read_as_bytes(&file.into())
                            .await
                            .map_err(|e| e.to_string())?;
                        let encrypted_name =
                            secret_share::encrypt_data(&key, name.as_bytes()).await?;
                        Ok((name, encrypted_name.to_string(), size, bytes))
                    }
                    .await;
                    Msg::FileRead(result)
                });
            }
        }
        Msg::FileRead(result) => match result {
            Ok((file_name, encrypted_file_name, size, content)) => {
                model
                    .files
                    .insert(file_name, (encrypted_file_name, size, content));
                model.drop_zone_active = false;
            }
            Err(e) => {
                model.drop_zone_active = false;
                model.error = Some(e);
            }
        },
        Msg::RemoveFile(file_name) => {
            model.files.remove(&file_name);
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
                p![&model.config.info],
                textarea![C!["card w-100"], style![St::Resize => "none"],
                    attrs![At::Id => "secret", At::Name => "secret", At::Rows => "10", At::Cols => "50", At::Value => model.get_secret(), At::ReadOnly => true]
                ]
                hr![],
                IF!(model.cryption_in_progress.is_some() =>
                    {
                        if let Some((cur, over)) = model.cryption_in_progress{
                            let percentage = 100 * cur / over;
                            let background = format!("linear-gradient(90deg, #eee {}%, white 0)", percentage);
                            div![C!["card"], style![St::TextAlign => "center", St::Background => background],
                                format!("Receiving and decrypting Files: {}/{}", cur, over)
                            ]
                        }else{
                            div![]
                        }
                    }
                ),
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
                                if !&model.config.info.is_empty() { "Reveal and download File(s)" } else { "Reveal" }
                            ]
                        ]
                    ]
                ),
                IF!(model.secret.is_some() && model.cryption_in_progress.is_none() && !model.blob_list.is_empty() => {
                    nodes![
                        p!["Save your files or they will be gone if you refresh/close this page: "],
                        div![style![St::Float => "left"],
                            model.blob_list.iter().map(|(blob_link, file_name)|
                                a![attrs![At::Href => blob_link, At::Download => file_name],
                                    style![St::Margin => "0.18em 0", St::Display => "block"],
                                    file_name
                                ]
                            ).collect::<Vec<_>>()
                        ]
                    ]
                }),
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
                    textarea![C!["col 6 card w-100"], style![St::Resize => "none", St::MarginBottom => em(-2)],
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
                            if let Some(data_transfer) = drag_event.data_transfer() {
                                data_transfer.set_effect_allowed("all");
                                data_transfer.set_drop_effect("copy");
                            }
                            Msg::DragOver
                        }),
                        ev(Ev::DragLeave, |event| {
                            stop_and_prevent!(event);
                            Msg::DragLeave
                        }),
                        ev(Ev::Drop, |event| {
                            let drag_event = event.dyn_into::<DragEvent>().expect("cannot cast given event into DragEvent");
                            stop_and_prevent!(drag_event);
                            let file_list = drag_event.data_transfer().expect("No data transfer").files().expect("No files");
                            Msg::Drop(file_list)
                        }),
                        IF!(model.files.is_empty() =>
                            input![
                                attrs![At::Type => "file", At::Multiple => "true"],
                                ev(Ev::Change, |event| {
                                    stop_and_prevent!(event);
                                    let element: HtmlInputElement = event.target().expect("no target found").dyn_into().expect("Could not cast element into HTMLInputElement");
                                    let file_list = element.files().expect("No files found");
                                    Msg::Drop(file_list)
                                }),
                            ]
                        ),
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
                            {let curr_size = Byte::from_u64(model.files.iter().fold(0, |acc, (_, (_, x, _))| acc + *x ));
                            let max_size = Byte::from_u64(model.config.max_files_size).get_appropriate_unit(byte_unit::UnitType::Binary);
                            format!("Max Size: {} / {}", curr_size.get_appropriate_unit(byte_unit::UnitType::Binary), max_size)}
                        ]
                    )
                ],
                div![C!["row"],
                    hr![]
                ],
                div![C!["row"],
                    IF!(model.uuid.is_some() && model.cryption_in_progress.is_none() =>
                        // div![C!["row"],
                        nodes![
                            div![C!["10 col"], style![St::PaddingRight => em(1), St::TextAlign => "center"],
                                pre![model.url()]
                            ],
                            div![C!["3 col"],
                                button![C!["card btn"], style![
                                    // St::VerticalAlign => St::from("text-bottom"),
                                    St::Width => percent(100)],
                                    input_ev(Ev::Click, |_| Msg::CopyUrl),
                                    model.clipboard_button_text.clone()
                                ]
                            ]
                        ]
                    ),
                    IF!(model.cryption_in_progress.is_some() =>
                        {
                            if let Some((cur, over)) = model.cryption_in_progress{
                                let percentage = 100 * cur / over;
                                let background = format!("linear-gradient(90deg, #eee {}%, white 0)", percentage);
                                div![C!["card"], style![St::TextAlign => "center", St::Background => background],
                                    format!("Encrypting and Sending Files: {}/{}", cur, over)
                                ]
                            } else {
                                div![]
                            }
                        }
                    ),
                    IF!(model.uuid.is_none() && model.cryption_in_progress.is_none() =>
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
