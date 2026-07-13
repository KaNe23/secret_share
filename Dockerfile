FROM scratch
COPY target/x86_64-unknown-linux-musl/release/secret_share /
COPY client_seed/dist/ /client_seed/dist/
EXPOSE 8080
CMD ["/secret_share"]