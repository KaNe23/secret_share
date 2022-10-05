# Secret Share
Share passwords or other secrets via an url, that is only readable once.
The secret is encrypted client side and the key is shared via the anchor of an url, which is not send to the server.

### Example:
`https://example_url.com/668d0fe2-b5ac-4c78-9e57-faa7c665b724#sXySruFg7KOhcWOe`

The UUID is a random reference for the secret: `668d0fe2-b5ac-4c78-9e57-faa7c665b724`

and the anchor is the 256 bits AES key: `sXySruFg7KOhcWOe`

Inspired by [onetimesecret](https://github.com/onetimesecret/onetimesecret)

### Pictures:

![enter_secret](https://github.com/KaNe23/secret_share/blob/master/pictures/enter_secret.png?raw=true)

![create_secret](https://github.com/KaNe23/secret_share/blob/master/pictures/create_secret.png?raw=true)

![view_secret](https://github.com/KaNe23/secret_share/blob/master/pictures/view_secret.png?raw=true)

![reveal_secret](https://github.com/KaNe23/secret_share/blob/master/pictures/reveal_secret.png?raw=true)

### CSS Used

https://ajusa.github.io/lit/

### Todo:
- add env vars for AES key length