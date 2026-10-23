# Writing your own client

How to create and read Payneteasy Secrets from your own program: a script, a CI job, a desktop or
mobile app. [FORMAT.md](FORMAT.md) is the exact specification; this guide walks through it in
order and lists the rules a client must keep. A working reference without dependencies is in
[`examples/node`](examples/node/sdrop-client.mjs).

Examples use `https://secrets.example.com`; use your service's address instead.

## What a client can be

- **A program, a script or an app**: anything that makes HTTP requests itself.
- **Not a web page on another site.** The API needs the `X-Secret-Drop: 1` header and allows no
  CORS, and requests that change something are refused when they carry a foreign `Origin`. A
  browser on another site cannot call the API; this keeps other sites from creating or burning
  secrets in a user's name.

## How it works

The client does all the cryptography. The server stores an opaque envelope and never sees the
key, the passphrase or the plaintext:

```
create:  K_url = 32 random bytes ──► envelope = AES-256-GCM(HKDF(K_url [+ PBKDF2(passphrase)]), plaintext)
         POST envelope ──► id, ownerToken
         recipient link: https://secrets.example.com/s/<id>#<K_url base64url>[~p]
         sender link:    https://secrets.example.com/o/<id>#<ownerToken>

read:    parse link ──► POST /api/secrets/<id>/consume ──► envelope (deleted on the server) ──► decrypt
```

The key travels only in the `#fragment`, which HTTP clients and browsers never send to a server.

## Rules every client must keep

1. **The key and the passphrase never leave the client.** Never send the fragment, never put it in
   a query string, a log, an analytics event, a crash report or a command-line argument (other
   users can see process arguments). The same goes for the plaintext and the sender link.
2. **One trusted origin.** Configure the service address once. Parse a link completely before any
   request: exactly that origin, `/s/` (recipient) or `/o/` (sender), an id of 64 lowercase hex
   characters, a fragment of 43 base64url characters that decodes to 32 bytes and encodes back to
   the same string (FORMAT.md 5). Anything else is a broken link and makes no request.
3. **Do not follow redirects.** A redirect means the service wants a login (see *Login* below); the
   request did not reach it and nothing was consumed.
4. **Reading destroys.** `consume` returns the envelope once and the server deletes it in the same
   request. Ask the user before calling it; never call it to preview, unfurl or check a link. Call
   it once per user action.
5. **Keep the envelope until it is decrypted.** If the passphrase is wrong, let the user try again
   with the envelope you already have: the server copy is gone. If saving to disk fails, keep the
   plaintext in memory and ask for another place.
6. **Passphrase.** If the link ends in `~p`, ask for the passphrase before consuming. The source of
   truth is the envelope flag: if it needs a passphrase and the link had no `~p`, ask after
   fetching.
7. **File names come from the sender.** Show them, but never use them as paths: save as `file-1`,
   `file-2`, … in a new directory only the user can read.
8. **The same answer for every miss.** Not found, already read, revoked, expired and invalid id are
   one indistinguishable 404. Say "not found, already read, revoked or expired; if you did not open
   it yourself, tell the sender".
9. **Wipe what you can.** Overwrite buffers holding keys, passphrases and plaintext after use where
   your language allows it.

## Creating a secret

1. **Ask the limit** (before encrypting, to tell the user early):

   ```
   GET /api/limits
   X-Secret-Drop: 1

   200 {"maxBucket":262144}
   ```

2. **Build the plaintext** (FORMAT.md 3, 4): one record per secret.
   - text only: `{"kind":"text","text":"…"}`, envelope version 1;
   - one file and no text: `{"kind":"file","name":"…","size":N}` followed by the bytes, version 1;
   - text with files, or several files: `{"kind":"bundle","text":"…","files":[{"name":"…","size":N},…]}`
     followed by the bytes in that order, version 2 (up to 20 files).

   The JSON must be in the canonical form (field order as shown, no spaces, `JSON.stringify` /
   `serde_json` escaping). Prefix it with its length as a big-endian `u32` and pad with zeros to the
   smallest bucket that fits (1024, 4096, 16384, 65536, 262144 or 1048576 bytes). A bucket above
   `maxBucket` is too large.

3. **Encrypt** (FORMAT.md 1, 2) with fresh random `K_url` (32 bytes), `salt` (16) and `iv` (12):
   - `ikm = K_url`, or `K_url || PBKDF2-HMAC-SHA256(UTF-8(NFC(passphrase)), salt, 600000, 32)`;
   - `K_enc = HKDF-SHA256(ikm, salt, "secret-drop v1 aes-256-gcm", 32)`;
   - header (34 bytes) = `"SDRP"`, version, flags (bit 0: passphrase), salt, iv;
   - envelope = header ‖ AES-256-GCM(K_enc, iv, plaintext, aad = header) (ciphertext with the tag).

4. **Upload**:

   ```
   POST /api/secrets?ttl=86400            (3600, 86400 or 604800 seconds)
   X-Secret-Drop: 1
   Content-Type: application/octet-stream

   <envelope>

   201 {"id":"<64 hex>","expiresAt":"2026-10-24T12:00:00.000Z","ownerToken":"<43 base64url>"}
   ```

5. **Build the links**: `https://secrets.example.com/s/<id>#<base64url(K_url)>`, with `~p`
   appended if there is a passphrase, for the recipient; `https://secrets.example.com/o/<id>#<ownerToken>`
   for the sender only. Tell the user to send the passphrase through a different channel.

## Reading a secret

1. Parse the link (rule 2). If it ends in `~p`, ask for the passphrase now.
2. Ask the user to confirm, then:

   ```
   POST /api/secrets/<id>/consume
   X-Secret-Drop: 1

   200 <envelope>          (application/octet-stream)
   404                      not found, already read, revoked or expired
   ```

   If the connection breaks during this request, the result is unknown: the secret may already be
   gone. Say so instead of retrying silently.
3. Decrypt (FORMAT.md 3, *Decryption order and errors*):
   - `corrupt` (bad header, or the plaintext fails a check): show "damaged", nothing else;
   - `need_passphrase`: ask for it and decrypt the same envelope again;
   - `decrypt_failed`: wrong passphrase (or a modified envelope); let the user retry locally.
4. Show the text; save files as in rule 7.

## Status and revoke (sender link)

```
GET /api/secrets/<id>/status
X-Secret-Drop: 1
Authorization: Bearer <ownerToken>

200 {"state":"stored","createdAt":"…","expiresAt":"…"}
200 {"state":"consumed","createdAt":"…","expiresAt":"…","consumedAt":"…"}
404  not found (or a wrong token)
```

`state` is `stored` (waiting to be opened), `consumed` (opened) or `revoked`. `consumedBy` (an
email) appears only on a service with login.

```
DELETE /api/secrets/<id>
X-Secret-Drop: 1
Authorization: Bearer <ownerToken>

204  revoked (a repeated revoke is fine)
409  already opened; the body is the status
404  not found or expired
```

With `curl`, the sender side looks like this (`$TOKEN` from the fragment of the sender link):

```sh
curl -s -H 'X-Secret-Drop: 1' -H "Authorization: Bearer $TOKEN" \
  https://secrets.example.com/api/secrets/$ID/status
```

## Other answers

| Answer | Meaning |
|---|---|
| 3xx | the service is behind Cloudflare Access and wants a login (below); not followed |
| 400 | malformed request: envelope length or header, `ttl`, `Content-Type` |
| 401, 403 | not allowed by the service's login |
| 413 `{"error":"too_large","maxBucket":N}` | the envelope is above the service limit |
| 429 | too many secrets created; wait a minute |

Responses carry `Cache-Control: no-store`; do not cache them either. An envelope is at most
1048626 bytes: refuse larger responses.

## Login (services behind Cloudflare Access)

A service may require a login. Then a request without it gets a redirect. Get a user token with
[`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/):

```sh
cloudflared access login https://secrets.example.com
cloudflared access token -app=https://secrets.example.com
```

and send it as the `cf-access-token` header with every request. The token identifies the user;
treat it like a password. Access service tokens are not accepted by the API.

## Testing your client

1. **Test vectors** in [`spec/`](spec/) (FORMAT.md 7), shared by every client:
   - `vectors.json`: encrypting with the given `salt` and `iv` must give exactly the envelope, and
     decrypting must give the secret back;
   - `vectors-invalid.json`: each envelope must be rejected with exactly the given error;
   - `links.json`: fragments to accept (with the key) and to reject.
2. **A check that fails**: break one rule on purpose (skip the canonical check, the padding check
   or NFC) and make sure some vector fails. A check that passes either way checks nothing.
3. **Against the service**: create with your client and read with `sdrop`, then the other way
   round, with and without a passphrase, text and files; a second read must give 404.

## Reference client

[`examples/node/sdrop-client.mjs`](examples/node/sdrop-client.mjs): Node.js 20 or later, no
dependencies (WebCrypto, `fetch`). It implements everything above and checks itself against the
vectors; CI runs the self-test.

```sh
node examples/node/sdrop-client.mjs selftest
export SDROP_ORIGIN=https://secrets.example.com
echo "db password" | node examples/node/sdrop-client.mjs put --ttl 3600 notes.txt
node examples/node/sdrop-client.mjs get -              # the link from stdin
node examples/node/sdrop-client.mjs status 'https://secrets.example.com/o/…'
```

The passphrase comes from `SDROP_PASSPHRASE` or is asked on the terminal.

## Compatibility

The format is versioned by the envelope `version` byte. Existing versions never change; anything
new comes with a new version. A client that does not know a version can only report "damaged"
after the secret is consumed, so keep clients up to date and reject unknown versions before
showing anything.
