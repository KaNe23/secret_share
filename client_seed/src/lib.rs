use seed::{prelude::*, *};

fn init(_: Url, _: &mut impl Orders<Msg>) -> SecretShare {
    SecretShare { }
}

struct SecretShare {
    
}

#[derive(Copy, Clone)]
enum Msg {
}


fn update(msg: Msg, model: &mut SecretShare, _: &mut impl Orders<Msg>) {
}

fn view(model: &SecretShare) -> Node<Msg> {
    div![
        "Secret Share"
    ]
}


#[wasm_bindgen(start)]
pub fn start() {
    // Mount the `app` to the element with the `id` "app".
    App::start("secret_share", init, update, view);
}
