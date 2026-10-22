# sdrop

Command line client for Payneteasy Secrets: one-time links for
passwords, keys and files. Everything is encrypted on your machine; the server keeps only the
ciphertext, and the key travels in the part of the link after `#`, which never reaches the server.
A link opens once and is then destroyed. The format is described in [FORMAT.md](FORMAT.md).

## Install

Download the binary for your platform from the
[latest release](https://github.com/payneteasy/sdrop/releases/latest):

| Platform | File |
|---|---|
| Linux x86_64 (static) | `sdrop-linux-x86_64` |
| Linux arm64 (static) | `sdrop-linux-aarch64` |
| macOS Apple Silicon | `sdrop-macos-arm64` |
| macOS Intel | `sdrop-macos-x86_64` |
| Windows x86_64 | `sdrop-windows-x86_64.exe` |

```sh
f=sdrop-macos-arm64
curl -fLO "https://github.com/payneteasy/sdrop/releases/latest/download/$f" &&
curl -fLO https://github.com/payneteasy/sdrop/releases/latest/download/SHA256SUMS &&
shasum -a 256 --ignore-missing -c SHA256SUMS &&
chmod +x "$f" && mv "$f" /usr/local/bin/sdrop
```

The chain stops at the first failure, so a file with a wrong checksum is never installed. On Linux
use `sha256sum` instead of `shasum -a 256`. To check that the binary was built by this
repository's CI: `gh attestation verify "$f" --repo payneteasy/sdrop` (before `mv`).

The macOS binaries are not notarized yet. Downloading with `curl` (as above) does not set the
quarantine flag; a file downloaded with a browser needs `xattr -d com.apple.quarantine sdrop`.

## Use

```sh
sdrop put < secret.txt                     # text from stdin; the recipient link goes to stdout
sdrop put --ttl 1h --passphrase < key.txt  # ask for a passphrase, link expires in an hour
sdrop put --file prod.key                  # a file as is
sdrop put --file prod.crt --file prod.key note.txt   # text and up to 20 files in one link
sdrop get 'https://secrets.example.com/s/…#…'        # text to stdout, files to ./sdrop-<id>/
sdrop get - -o ./received < link.txt                 # link from stdin, output to a new path
sdrop status 'https://secrets.example.com/o/…#…'     # the sender link: read or not
sdrop revoke 'https://secrets.example.com/o/…#…'
```

- `put` prints the recipient link to stdout and the sender link (status, revoke) to stderr, so
  `sdrop put < f | pbcopy` copies only the link to send.
- A secret or passphrase is never taken from the command line arguments: only stdin, a file
  (`--passphrase-file`, first line) or the terminal without echo. Pass a link as `-` to read it
  from stdin and keep the key out of the shell history.
- With `--file`, text is taken only from an explicit input (a path or `-` for stdin).
- `get` saves files into a new private directory (`0700`, files `0600`) under names it chooses
  (`data`, `file-1`, …); the sender's file names are only shown, never used as paths.
- If writing fails after the secret was fetched (it is already deleted on the server), `get` asks
  for another path in the terminal or falls back to a new directory in the current one. An empty
  answer asks again; Ctrl+D on an empty line (also on Windows) stops asking and tries the default
  directory.

### Interactive mode

`sdrop` without arguments on a terminal (or `sdrop tui`) opens a full-screen interface:

- **New secret**: text, files by path (up to 20), lifetime, passphrase (**Ctrl+G** generates
  one when the passphrase is on); the size is shown against the service limit. **Ctrl+S** creates
  the link from any field (Shift/Cmd/Alt+Enter too, in terminals that report the modifier: kitty,
  WezTerm, Ghostty, Alacritty, iTerm2 with CSI u).
- **Link ready**: the recipient link with **c** to copy; your private sender link (track or
  revoke) stays hidden until **o**, **y** copies it.
- **Open a link**: nothing is sent until you confirm; the text is shown, files are saved into a
  new private directory; a passphrase can be retried without fetching again.
- **Check status**: waiting to be opened, opened or revoked (times in UTC); revoke.
- **Keys**: Tab / Shift+Tab move the focus, Enter or Space presses the focused button, the letter
  in parentheses presses it from anywhere on the screen, Esc goes back. The focus is shown as
  `> … <` and the chosen option as `(*)`, so the screen reads without color too.
- **Confirmations**: revoking, leaving received files unsaved and discarding a downloaded secret
  that still needs its passphrase ask first; the safe choice is focused, Esc cancels.
- **Window**: at least 80×24; a smaller window shows only a note, nothing typed or received is
  lost.
- **Colors**: the brand accents in 24-bit color, else the 256-color palette (Terminal.app);
  `NO_COLOR` turns them off.
- **Mouse**: click fields, options and buttons; the wheel scrolls. While the mouse is captured,
  select text in the terminal with Option (macOS) or Shift (Linux, Windows) held.
- **Clipboard**: the system clipboard on this machine; over SSH, the terminal's OSC 52 (the
  clipboard of the machine you sit at). A copied secret text is removed from the clipboard after
  60 seconds (and on exit) if it is still there; links are not. Clipboard managers may keep a
  history: `sdrop` warns before the first copy.
- The screen is cleared before `sdrop` leaves its own screen, also on errors, so a secret does not
  stay in the terminal's scrollback. What was shown passes through the terminal's own memory,
  which `sdrop` cannot wipe.

### Settings

| Variable | Meaning |
|---|---|
| `SDROP_ORIGIN` | the service, e.g. `https://secrets.example.com`; overrides the one built in |
| `SDROP_ACCESS_TOKEN` | a Cloudflare Access token, if the service requires login |

`sdrop` talks only to that one origin: a link to any other host is rejected before any request,
redirects are not followed. If the service is behind Cloudflare Access and no token is set,
`sdrop` runs `cloudflared access login` and `cloudflared access token` for you.

On Windows the passphrase and the save path are read from the console; file permissions follow
the ACL of the target directory.

## Build

```sh
SDROP_DEFAULT_ORIGIN=https://secrets.example.com cargo build --release   # the built-in service
```

## Tests

```sh
cargo test                            # format vectors (spec/), shared with the browser client
cargo test --features test-loopback   # commands against a local fake server
```

The `test-loopback` feature exists only for tests: it allows `http://127.0.0.1:<port>` and reads
tokens only from `SDROP_TEST_*` variables. Release binaries are built without it and refuse
`http://`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
