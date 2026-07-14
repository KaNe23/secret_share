mod crypto;

use std::collections::HashMap;

use byte_unit::{Byte, UnitType};
use js_sys::Uint8Array;
use leptos::prelude::*;
use leptos::task::spawn_local;
use rand::distr::Alphanumeric;
use rand::{rng, RngExt};
use serde::{Deserialize, Serialize};
use shared::{Config, EncryptedData, Lifetime};
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{DragEvent, FileList, HtmlInputElement};

const KEY_LEN: usize = 32; // AES-256 needs a 32 byte key

#[derive(Clone)]
struct FileEntry {
    name: String,
    size: u64,
    bytes: Vec<u8>,
}

fn get_config() -> Config {
    web_sys::window()
        .and_then(|window| js_sys::Reflect::get(&window, &"config".into()).ok())
        .and_then(|value| serde_wasm_bindgen::from_value(value).ok())
        .unwrap_or_default()
}

enum Mode {
    Create(String),     // fresh encrypt key
    View(Uuid, String), // uuid + decrypt key from the url
    Broken(String),     // unusable link
}

fn get_mode() -> Mode {
    let url = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.url().ok())
        .and_then(|url| web_sys::Url::new(&url).ok());

    if let Some(url) = url {
        let pathname = url.pathname();
        let hash = url.hash();

        if let Ok(uuid) = Uuid::parse_str(pathname.trim_start_matches('/')) {
            return if hash.is_empty() {
                Mode::Broken("decrypt key missing from url".to_string())
            } else if hash.len() - 1 != KEY_LEN {
                Mode::Broken("decrypt key has invalid length".to_string())
            } else {
                // hash contains # as first char
                Mode::View(uuid, hash.trim_start_matches('#').to_string())
            };
        }
    }

    let key = rng()
        .sample_iter(Alphanumeric)
        .take(KEY_LEN)
        .map(char::from)
        .collect::<String>();
    Mode::Create(key)
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
    key: &str,
    uuid: Uuid,
    encrypted_name: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let blob = crypto::encrypt_blob(key, bytes).await?;
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
    key: &str,
    uuid: Uuid,
    encrypted_name: &str,
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
    let bytes = crypto::decrypt_blob(key, &blob).await?;

    let encrypted: EncryptedData = encrypted_name
        .parse()
        .map_err(|_| "Invalid file name".to_string())?;
    let name_bytes = crypto::decrypt_data(key, &encrypted).await?;
    let file_name = String::from_utf8(name_bytes).map_err(|e| e.to_string())?;

    Ok((file_name, bytes))
}

/// Encrypt everything, create the secret, then upload the files one by one.
async fn create_secret(
    key: String,
    text: String,
    password: String,
    lifetime: Lifetime,
    files: Vec<FileEntry>,
    progress: RwSignal<Option<(usize, usize)>>,
) -> Result<Uuid, String> {
    let secret = crypto::encrypt_data(&key, text.as_bytes()).await?;

    let mut encrypted_files = Vec::new();
    for file in &files {
        let encrypted_name = crypto::encrypt_data(&key, file.name.as_bytes())
            .await?
            .to_string();
        encrypted_files.push((encrypted_name, file));
    }

    let file_list: HashMap<String, u64> = encrypted_files
        .iter()
        .map(|(name, file)| (name.clone(), file.size))
        .collect();

    let request = shared::Request::CreateSecret {
        secret,
        password: (!password.is_empty()).then_some(password),
        lifetime,
        file_list,
    };

    let uuid = match send_request(&request, "/new_secret").await? {
        shared::Response::Uuid(uuid) => uuid,
        shared::Response::Error(e) => return Err(e),
        _ => return Err("Unexpected response".to_string()),
    };

    if !encrypted_files.is_empty() {
        progress.set(Some((0, encrypted_files.len())));
        for (index, (encrypted_name, file)) in encrypted_files.iter().enumerate() {
            upload_file(&key, uuid, encrypted_name, &file.bytes).await?;
            progress.set(Some((index + 1, encrypted_files.len())));
        }
        progress.set(None);
    }

    Ok(uuid)
}

/// Fetch and decrypt the secret, then download and decrypt each file.
async fn reveal_secret(
    key: String,
    uuid: Uuid,
    password: String,
    secret: RwSignal<Option<String>>,
    blobs: RwSignal<Vec<(String, String)>>,
    progress: RwSignal<Option<(usize, usize)>>,
) -> Result<(), String> {
    let (encrypted, file_names) = match send_request(
        &shared::Request::GetSecret { uuid, password },
        "/get_secret",
    )
    .await?
    {
        shared::Response::Secret((encrypted, file_names)) => (encrypted, file_names),
        shared::Response::Error(e) => return Err(e),
        _ => return Err("Unexpected response".to_string()),
    };

    let text = crypto::decrypt_data(&key, &encrypted).await?;
    secret.set(Some(String::from_utf8(text).map_err(|e| e.to_string())?));

    if !file_names.is_empty() {
        progress.set(Some((0, file_names.len())));
        for (index, encrypted_name) in file_names.iter().enumerate() {
            let (file_name, bytes) = download_file(&key, uuid, encrypted_name).await?;
            let file = gloo_file::File::new(&file_name, bytes.as_slice());
            let blob = gloo_file::Blob::from(file);
            let url = web_sys::Url::create_object_url_with_blob(&blob.into())
                .map_err(|_| "Could not create download link".to_string())?;
            blobs.update(|list| list.push((url, file_name)));
            progress.set(Some((index + 1, file_names.len())));
        }
        progress.set(None);
    }

    Ok(())
}

fn abbreviate(file_name: &str) -> String {
    if file_name.chars().count() > 35 {
        let head: String = file_name.chars().take(35).collect();
        let tail: String = file_name
            .chars()
            .skip(file_name.chars().count() - 3)
            .collect();
        format!("{}…{}", head, tail)
    } else {
        file_name.to_string()
    }
}

fn progress_bar(progress: RwSignal<Option<(usize, usize)>>, label: &'static str) -> impl IntoView {
    move || {
        progress.get().map(|(current, total)| {
            let percentage = 100 * current / total.max(1);
            let background = format!("linear-gradient(90deg, #eee {}%, white 0)", percentage);
            view! {
                <div class="card" style:text-align="center" style:background=background>
                    {format!("{} Files: {}/{}", label, current, total)}
                </div>
            }
        })
    }
}

#[component]
fn ViewSecret(config: Config, uuid: Uuid, key: String) -> impl IntoView {
    let password = RwSignal::new(String::new());
    let secret = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let progress = RwSignal::new(None::<(usize, usize)>);
    let blobs = RwSignal::new(Vec::<(String, String)>::new());

    let info = config.info.clone();
    let reveal_label = if config.info.is_empty() {
        "Reveal"
    } else {
        "Reveal and download File(s)"
    };
    let password_required = config.password_required;

    let on_reveal = move |_| {
        let key = key.clone();
        spawn_local(async move {
            error.set(None);
            if let Err(e) = reveal_secret(
                key,
                uuid,
                password.get_untracked(),
                secret,
                blobs,
                progress,
            )
            .await
            {
                progress.set(None);
                error.set(Some(e));
            }
        });
    };

    view! {
        <h1>"View secret"</h1>
        <h5>"This can only be done ONCE!"</h5>
        <p>{move || error.get()}</p>
        <p>{info}</p>
        <textarea
            class="card w-100"
            style:resize="none"
            id="secret"
            name="secret"
            rows="10"
            cols="50"
            readonly
            prop:value=move || secret.get().unwrap_or_default()
        ></textarea>
        <hr/>
        {progress_bar(progress, "Receiving and decrypting")}
        {move || secret.get().is_none().then(|| view! {
            <div class="row" style:border-spacing="0 0">
                {password_required.then(|| view! {
                    <div class="3 col" style:padding-right="1em">
                        <input
                            class="card"
                            type="password"
                            name="password"
                            placeholder="Password required"
                            prop:value=move || password.get()
                            on:change=move |ev| password.set(event_target_value(&ev))
                        />
                    </div>
                })}
                <div class="col">
                    <button class="btn primary" on:click=on_reveal.clone()>{reveal_label}</button>
                </div>
            </div>
        })}
        {move || (secret.get().is_some() && progress.get().is_none() && !blobs.get().is_empty()).then(|| view! {
            <p>"Save your files or they will be gone if you refresh/close this page: "</p>
            <div style:float="left">
                {blobs.get().into_iter().map(|(url, file_name)| {
                    let label = file_name.clone();
                    view! {
                        <a href=url download=file_name style:margin="0.18em 0" style:display="block">
                            {label}
                        </a>
                    }
                }).collect_view()}
            </div>
        })}
    }
}

#[component]
fn CreateSecret(config: Config, key: String) -> impl IntoView {
    let secret = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let lifetime = RwSignal::new(Lifetime::default());
    let files = RwSignal::new(Vec::<FileEntry>::new());
    let error = RwSignal::new(None::<String>);
    let share_url = RwSignal::new(None::<String>);
    let progress = RwSignal::new(None::<(usize, usize)>);
    let drop_active = RwSignal::new(false);
    let clipboard_text = RwSignal::new("Copy to Clipboard".to_string());

    let max_files = config.max_files as usize;
    let max_files_size = config.max_files_size;
    let max_length = config.max_length;
    let lifetimes = config.lifetimes.clone();
    let base_url = config.base_url.clone();

    let add_files = move |file_list: FileList| {
        drop_active.set(false);
        // `FileList` doesn't implement `Iterator`.
        let new_files = (0..file_list.length())
            .filter_map(|index| file_list.get(index))
            .collect::<Vec<_>>();

        if new_files.len() + files.get_untracked().len() > max_files {
            error.set(Some(format!("Only {} files allowed.", max_files)));
            return;
        }

        let new_size = new_files.iter().fold(0, |acc, f| acc + f.size() as u64);
        let current_size = files.get_untracked().iter().fold(0, |acc, f| acc + f.size);
        if new_size + current_size > max_files_size {
            let max = Byte::from_u64(max_files_size).get_appropriate_unit(UnitType::Binary);
            error.set(Some(format!("Max acc. file size of {} exceeded.", max)));
            return;
        }

        for file in new_files {
            spawn_local(async move {
                let name = file.name();
                let size = file.size() as u64;
                match gloo_file::futures::read_as_bytes(&file.into()).await {
                    Ok(bytes) => files.update(|list| {
                        list.retain(|f| f.name != name);
                        list.push(FileEntry { name, size, bytes });
                    }),
                    Err(e) => error.set(Some(e.to_string())),
                }
            });
        }
    };

    let on_create = {
        let key = key.clone();
        let base_url = base_url.clone();
        move |_| {
            let key = key.clone();
            let base_url = base_url.clone();
            spawn_local(async move {
                error.set(None);
                match create_secret(
                    key.clone(),
                    secret.get_untracked(),
                    password.get_untracked(),
                    lifetime.get_untracked(),
                    files.get_untracked(),
                    progress,
                )
                .await
                {
                    Ok(uuid) => share_url.set(Some(format!("{}/{}#{}", base_url, uuid, key))),
                    Err(e) => {
                        progress.set(None);
                        error.set(Some(e));
                    }
                }
            });
        }
    };

    let on_copy = move |_| {
        if let Some(url) = share_url.get_untracked() {
            let clipboard = window().navigator().clipboard();
            let promise = clipboard.write_text(&url);
            spawn_local(async move {
                let result = JsFuture::from(promise).await;
                clipboard_text.set(if result.is_ok() {
                    "Success!".to_string()
                } else {
                    "Failure! :(".to_string()
                });
            });
        }
    };

    view! {
        <div class="row">
            <h1>"Create new secret"</h1>
            // trailing space keeps the element height stable when there is no error
            <p>{move || error.get()}" "</p>
        </div>
        <div class="row">
            <textarea
                class="col 6 card w-100"
                style:resize="none"
                style:margin-bottom="-2em"
                id="secret"
                name="secret"
                rows="10"
                cols="50"
                maxlength=max_length
                on:input=move |ev| secret.set(event_target_value(&ev))
            ></textarea>
            <div
                class=move || if drop_active.get() || !files.get().is_empty() { "col 6 card w-50" } else { "col 3 card w-50" }
                style:border-style="dashed"
                style:border-radius="20px"
                style:transition="width 0.25s ease-out"
                on:dragenter=move |ev: DragEvent| {
                    ev.stop_propagation();
                    ev.prevent_default();
                    drop_active.set(true);
                }
                on:dragover=move |ev: DragEvent| {
                    ev.stop_propagation();
                    ev.prevent_default();
                    if let Some(data_transfer) = ev.data_transfer() {
                        data_transfer.set_effect_allowed("all");
                        data_transfer.set_drop_effect("copy");
                    }
                }
                on:dragleave=move |ev: DragEvent| {
                    ev.stop_propagation();
                    ev.prevent_default();
                    drop_active.set(false);
                }
                on:drop=move |ev: DragEvent| {
                    ev.stop_propagation();
                    ev.prevent_default();
                    if let Some(file_list) = ev.data_transfer().and_then(|dt| dt.files()) {
                        add_files(file_list);
                    }
                }
            >
                {move || files.get().is_empty().then(|| view! {
                    <input
                        type="file"
                        multiple
                        on:change=move |ev| {
                            let element: HtmlInputElement = event_target(&ev);
                            if let Some(file_list) = element.files() {
                                add_files(file_list);
                            }
                        }
                    />
                })}
                <div style:float="left">
                    {move || files.get().into_iter().map(|file| {
                        let name = file.name.clone();
                        view! {
                            <div style:margin="0.18em 0">
                                <div
                                    style:float="left"
                                    style:cursor="pointer"
                                    style:padding-right="5px"
                                    on:click=move |_| files.update(|list| list.retain(|f| f.name != name))
                                >
                                    "❌"
                                </div>
                                {abbreviate(&file.name)}
                            </div>
                        }
                    }).collect_view()}
                </div>
            </div>
        </div>
        <div class="row">
            <p class="4 col" style:text-align="left" style:color="#aaa">
                {move || format!("Text: {} / {}", secret.get().len(), max_length)}
            </p>
            <p class="2 col" style:color="#aaa"
                style:text-align=move || if files.get().is_empty() { "right" } else { "center" }
            >
                {move || format!("Files: {} / {}", files.get().len(), max_files)}
            </p>
            {move || (!files.get().is_empty()).then(|| view! {
                <p class="3 col" style:text-align="right" style:color="#aaa">
                    {move || {
                        let current = Byte::from_u64(files.get().iter().fold(0, |acc, f| acc + f.size))
                            .get_appropriate_unit(UnitType::Binary);
                        let max = Byte::from_u64(max_files_size).get_appropriate_unit(UnitType::Binary);
                        format!("Max Size: {} / {}", current, max)
                    }}
                </p>
            })}
        </div>
        <div class="row"><hr/></div>
        <div class="row">
            {move || (share_url.get().is_some() && progress.get().is_none()).then(|| view! {
                <div class="10 col" style:padding-right="1em" style:text-align="center">
                    <pre>{share_url.get().unwrap_or_default()}</pre>
                </div>
                <div class="3 col">
                    <button class="card btn" style:width="100%" on:click=on_copy>
                        {move || clipboard_text.get()}
                    </button>
                </div>
            })}
            {progress_bar(progress, "Encrypting and Sending")}
            {move || (share_url.get().is_none() && progress.get().is_none()).then(|| view! {
                <input
                    class="card"
                    type="password"
                    name="password"
                    placeholder="Optional password"
                    prop:value=move || password.get()
                    on:change=move |ev| password.set(event_target_value(&ev))
                />
                <label style:margin-left="1em" style:color="#777">"Lifetime:"</label>
                <select
                    class="card w-10"
                    style:margin-left="1em"
                    on:change=move |ev| {
                        if let Ok(parsed) = event_target_value(&ev).parse() {
                            lifetime.set(parsed);
                        }
                    }
                >
                    {lifetimes.iter().map(|lt| view! {
                        <option value=lt.to_string() selected=*lt == lifetime.get_untracked()>
                            {lt.long_string()}
                        </option>
                    }).collect_view()}
                </select>
                <button class="btn primary" style:float="right" on:click=on_create.clone()>
                    "Create"
                </button>
            })}
        </div>
    }
}

#[component]
fn App() -> impl IntoView {
    let config = get_config();

    // if the server could not find the secret we bail out directly
    let mode = if config.error.is_empty() {
        get_mode()
    } else {
        Mode::Broken(config.error.clone())
    };

    view! {
        <div class="c">
            {match mode {
                Mode::Broken(message) => view! { <p>{message}</p> }.into_any(),
                Mode::View(uuid, key) => {
                    view! { <ViewSecret config=config uuid=uuid key=key/> }.into_any()
                }
                Mode::Create(key) => {
                    view! { <CreateSecret config=config key=key/> }.into_any()
                }
            }}
        </div>
    }
}

#[wasm_bindgen(start)]
pub fn start() {
    leptos::mount::mount_to_body(App);
}
