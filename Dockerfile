# debian-based builder: trunk's downloaded helper tools (wasm-bindgen, wasm-opt)
# are glibc binaries; the server itself cross-builds to musl for the scratch image
FROM rust:1-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown x86_64-unknown-linux-musl
RUN wget -qO- https://github.com/trunk-rs/trunk/releases/latest/download/trunk-x86_64-unknown-linux-gnu.tar.gz \
    | tar -xzf - -C /usr/local/bin
WORKDIR /app
COPY . .
# frontend first: the server bakes client/dist/index.html into the binary
# (askama), so the build order here is load-bearing
RUN trunk build --release
RUN cargo build --release

FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/secret_share /
COPY --from=builder /app/client/dist/ /client/dist/
EXPOSE 8080
CMD ["/secret_share"]
