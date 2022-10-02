use if_chain::if_chain;
use seed::{
    attrs, br, button, div, h1, hr, input, label, option, p, pre, prelude::*, select, style,
    textarea, virtual_dom::Node, C,
};
use shared::Config;

#[derive(Debug, Default)]
struct SecretShare {
    lifetime: shared::Lifetime,
    lifetimes: Vec<shared::Lifetime>,
}

impl SecretShare {
    fn lifetime_options(&self) -> Vec<Node<Msg>> {
        self.lifetimes
            .iter()
            .map(|lifetime| {
                option![
                    attrs! {
                        At::Value => lifetime.to_string(),
                        At::Selected => (*lifetime == self.lifetime).as_at_value()
                    },
                    lifetime.long_string()
                ]
            })
            .collect()
    }
}

#[derive(Copy, Clone)]
enum Msg {}

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
    SecretShare {
        lifetimes: config.lifetimes,
        ..Default::default()
    }
}

fn update(msg: Msg, model: &mut SecretShare, _: &mut impl Orders<Msg>) {}

fn view(model: &SecretShare) -> Node<Msg> {
    div![
        C!["c"],
        h1!["Create new secret"],
        p![],
        textarea![
            C!["card w-100"],
            style![St::Resize => "none"],
            attrs![At::MaxLength => 123, At::Id => "secret", At::Name => "secret",  At::Rows => "10",  At::Cols => "50"]
        ],
        div![
            C!["row"],
            style![St::BorderSpacing => "0 0"],
            input![
                C!["card"],
                attrs![At::Value => "", At::Type => "password", At::Name => "password", At::Placeholder => "Optional password"]
            ],
            label![
                style![St::MarginLeft => em(1), St::Color => "#777"],
                "Lifetime:"
            ],
            select![
                C!["card w-10"],
                style![St::MarginLeft => em(1)],
                model.lifetime_options()
            ],
            p![
                C!["3 col"],
                style![St::TextAlign => St::Right, St::Color => "#aaa"],
                "0 / 10000"
            ]
        ],
        hr![],
        div![div![
            C!["row"],
            style![St::BorderSpacing => "0 0"],
            div![
                C!["10 col"],
                style![St::PaddingRight => em(1)],
                pre!["Some Link"]
            ],
            div![
                C!["3 col"],
                button![
                    C!["card btn"],
                    style![St::VerticalAlign => St::from("text-bottom"), St::Width => percent(100)],
                    "Copy to Clipboard."
                ]
            ]
        ]],
        button![C!["btn primary"], "Create"],
        br![],
        br![],
    ]
}

#[wasm_bindgen(start)]
pub fn start() {
    App::start("secret_share", init, update, view);
}
