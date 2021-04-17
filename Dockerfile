FROM scratch
COPY target/x86_64-unknown-linux-musl/release/secret_share /
COPY server/templates/index.html /templates/
COPY client/pkg/bundle.js /client/pkg/
COPY client/pkg/client_bg.wasm /client/pkg/
EXPOSE 8080
CMD ["/secret_share"]