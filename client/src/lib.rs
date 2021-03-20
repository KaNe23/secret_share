pub mod app;

use wasm_bindgen::prelude::*;

pub struct NomNom{}

#[wasm_bindgen]
pub fn run_app() -> Result<(), JsValue> {
    yew::start_app::<app::App>();

    Ok(())
}