use anyhow::Error;

use serde::{Deserialize, Serialize};

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
    secret: String,
    tasks: Vec<FetchTask>,
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
    UrlCreated(String),
    Error,
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            secret: "".to_string(),
            tasks: vec![],
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::CreateSecret => {
                ConsoleService::info(&"CreateSecret:");

                let body = CreateSecretRequest {
                    secret: self.secret.clone(),
                };

                let post_request = Request::post("/new_secret")
                    .header("Content-Type", "application/json")
                    .body(Json(&body))
                    .unwrap();

                let res_cb = self.link.callback(
                    |response: Response<Json<Result<CreateSecretResponse, Error>>>| {
                        if let (_meta, Json(Ok(res))) = response.into_parts() {
                            Msg::UrlCreated(res.uuid)
                        } else {
                            Msg::Error
                        }
                    },
                );

                let task = FetchService::fetch(post_request, res_cb).unwrap();

                self.tasks.push(task);
            }
            Msg::UpdateSecret(secret) => {
                self.secret = secret;
            }
            Msg::UrlCreated(url) => ConsoleService::info(&format!("url: {:?}", url)),
            Msg::Error => {}
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

        html! {
            <>
                <h1>{ "Create new secret" }</h1>
                <br/>
                <form action="/new_secret" method="post">
                    <label for="secret">{ "Secret:" }</label>
                    <textarea id="secret" name="secret" rows="4" cols="50" oninput=update_secret value=&self.secret></textarea>
                    <br/>
                    <br/>
                </form>
                <button onclick=create_secret>{ "Submit" }</button>
            </>
        }
    }
}
