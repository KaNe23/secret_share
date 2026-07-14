# Secret Share

Share passwords, other secrets and files via a URL that is only readable **once**.

Everything is encrypted end-to-end in the browser with AES-256-GCM via the
[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto).
The key travels only in the URL fragment (the part after `#`), which browsers
never send to the server — the server stores nothing but ciphertext.

### Example

`https://example.com/668d0fe2-b5ac-4c78-9e57-faa7c665b724#sXySruFg7KOhcWOesXySruFg7KOhcWOe`

- `668d0fe2-b5ac-4c78-9e57-faa7c665b724` — random reference for the secret
- `sXySruFg7KOhcWOe…` — the 256-bit AES key, only ever present in the fragment

Inspired by [onetimesecret](https://github.com/onetimesecret/onetimesecret).

### Features

- **One-time read** — the first successful read atomically deletes the secret;
  two concurrent readers can never both receive it
- **File attachments** — encrypted in the browser like the text secret, file
  names included
- **Configurable lifetime** — 5 minutes to 7 days; expired secrets are swept
  automatically
- **Optional password** — bcrypt-hashed, verified server-side inside the same
  atomic read-and-delete
- **No external services** — storage is an embedded [redb](https://github.com/cberner/redb)
  database: one static binary, one data file
- Tiny deployment: statically linked musl binary in a `FROM scratch` container

### Architecture

| Piece | Tech |
|---|---|
| Server | [actix-web](https://actix.rs), [redb](https://github.com/cberner/redb) embedded storage |
| Frontend | Rust → WebAssembly ([seed](https://seed-rs.org)), built with [trunk](https://trunkrs.dev) |
| Crypto | AES-256-GCM via the browser's native `crypto.subtle` — no crypto code in the wasm bundle |

The server is crypto-agnostic: it stores opaque ciphertext with a TTL and
deletes it on first read. Uploads are validated against the declared file list
and size limits.

### Build & run

Requirements: Rust (stable), `trunk` (`cargo install trunk`), and the
`wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`).
The default build target is `x86_64-unknown-linux-musl` (see `.cargo/config.toml`).

```sh
# build the frontend, then run the server
trunk build --release client_seed/index.j2
cargo run --release
```

Or with Docker:

```sh
trunk build --release client_seed/index.j2
cargo build --release
docker compose up --build
```

### Configuration

All via environment variables:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Listen port |
| `BASE_URL` | `http://localhost:8080` | Base URL used in generated share links |
| `DB_PATH` | `secret_share.redb` | Path of the embedded database file |
| `MAX_LENGTH` | `10000` | Maximum secret text length |
| `MAX_FILES` | `5` | Maximum number of attached files |
| `MAX_FILES_SIZE` | `25 MiB` | Maximum accumulated file size, e.g. `50mb`, `1GiB` |

### Pictures

![enter_secret](https://github.com/KaNe23/secret_share/blob/main/pictures/enter_secret.png?raw=true)

![create_secret](https://github.com/KaNe23/secret_share/blob/main/pictures/create_secret.png?raw=true)

![view_secret](https://github.com/KaNe23/secret_share/blob/main/pictures/view_secret.png?raw=true)

![reveal_secret](https://github.com/KaNe23/secret_share/blob/main/pictures/reveal_secret.png?raw=true)

### CSS

[lit](https://ajusa.github.io/lit/) — a tiny classless-ish CSS framework.
