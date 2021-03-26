# requirements:
- wasm-pack
- rollup with rollup-plugin-postcss

~/.cargo/bin/wasm-pack build client --target web &&
rollup -p rollup-plugin-postcss client/static/main.js --format iife --file client/pkg/bundle.js &&
cargo run