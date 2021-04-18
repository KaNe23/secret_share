# requirements:
- rust
- wasm-pack
- rollup with rollup-plugin-postcss
- musl
- (rustup target add x86_64-unknown-linux-musl)

# build and run locally
wasm-pack build client --release --target web &&
rollup -p rollup-plugin-postcss client/static/main.js --format iife --file client/pkg/bundle.js &&
cargo run --release

# build and run in scratch container
wasm-pack build client --release --target web &&
rollup -p rollup-plugin-postcss client/static/main.js --format iife --file client/pkg/bundle.js &&
cargo build --release --workspace --exclude client &&
docker rmi secret_share &&
docker build -t secret_share . &&
docker run --rm --name secret_share -p 127.0.0.1:8080:8080 -it secret_share

# build container
docker create --name secret_share secret_share:latest


strip target/x86_64-unknown-linux-musl/release/secret_share &&
# go super nuts
wasm-pack build client --release --target web &&
rollup -p rollup-plugin-postcss client/static/main.js --format iife --file client/pkg/bundle.js &&
cargo build --release --workspace --exclude client &&
sstrip target/x86_64-unknown-linux-musl/release/secret_share &&
upx --best --lzma target/x86_64-unknown-linux-musl/release/secret_share