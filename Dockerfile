FROM scratch
COPY target/x86_64-unknown-linux-musl/release/secret_share /
COPY client/dist/ /client/dist/
EXPOSE 8080
CMD ["/secret_share"]