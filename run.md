~/.cargo/bin/wasm-pack build client --target web &&
rollup client/main.js --format iife --file client/pkg/bundle.js &&
cargo run