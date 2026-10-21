//! put / get / status / revoke subcommands (README).

use crate::access;
use crate::api::{self, CliError, Origin, err, http_error};
use crate::format::{self, FormatError, Secret};
use serde_json::Value;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Message to stderr without panicking: after consume, a failure to print diagnostics must not
/// prevent saving the secret (README).
macro_rules! note {
    ($($a:tt)*) => {{
        let _ = writeln!(std::io::stderr(), $($a)*);
    }};
}

/// Input read limit: above the maximum secret, but not unbounded.
const MAX_INPUT: u64 = 1 << 20;

pub fn ttl_seconds(ttl: &str) -> Result<u32, CliError> {
    match ttl {
        "1h" => Ok(3600),
        "24h" => Ok(86400),
        "7d" => Ok(604800),
        _ => err("--ttl must be 1h, 24h or 7d"),
    }
}

/// Input: a file or stdin ("-" or nothing). UTF-8 only.
pub fn read_input(file: Option<&Path>) -> Result<Zeroizing<String>, CliError> {
    let mut buf = Zeroizing::new(Vec::new());
    let read = match file {
        Some(p) if p != Path::new("-") => std::fs::File::open(p)
            .map_err(|_| {
                CliError::Msg(format!(
                    "cannot read {}",
                    api::printable(&p.display().to_string())
                ))
            })?
            .take(MAX_INPUT)
            .read_to_end(&mut buf),
        _ => std::io::stdin().take(MAX_INPUT).read_to_end(&mut buf),
    };
    read.map_err(|_| CliError::Msg("cannot read the input".into()))?;
    if buf.len() as u64 >= MAX_INPUT {
        return Err(FormatError::TooLarge.into());
    }
    match std::str::from_utf8(&buf) {
        Ok(s) => Ok(Zeroizing::new(s.to_owned())),
        Err(_) => err("the input is not UTF-8 text (binary files are not supported)"),
    }
}

/// Passphrase from a file: the first line without the newline.
pub fn read_passphrase_file(p: &Path) -> Result<Zeroizing<String>, CliError> {
    let s = read_input(Some(p))?;
    let line = s.split('\n').next().unwrap_or("").trim_end_matches('\r');
    if line.is_empty() {
        return Err(FormatError::EmptyPassphrase.into());
    }
    Ok(Zeroizing::new(line.to_owned()))
}

/// Line from the terminal without echo (may be empty). In the test build the "terminal" is
/// the lines of the SDROP_TEST_TTY_INPUT file.
fn read_tty(label: &str) -> Result<Zeroizing<String>, CliError> {
    tty_line(label)
        .map(Zeroizing::new)
        .map_err(|_| CliError::Msg("cannot read the passphrase from the terminal".into()))
}

/// Passphrase from the terminal before any network I/O: empty is an error.
fn prompt(label: &str) -> Result<Zeroizing<String>, CliError> {
    let p = read_tty(label)?;
    if p.is_empty() {
        return Err(FormatError::EmptyPassphrase.into());
    }
    Ok(p)
}

#[cfg(not(feature = "test-loopback"))]
fn tty_line(label: &str) -> std::io::Result<String> {
    rpassword::prompt_password(label)
}

/// Line from the terminal with echo (the save path): `/dev/tty`, so it works with stdin and
/// stdout redirected.
#[cfg(all(unix, not(feature = "test-loopback")))]
fn tty_plain_line(label: &str) -> std::io::Result<String> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    tty.write_all(label.as_bytes())?;
    read_console_line(tty)
}

/// Windows: the console (`CONIN$`/`CONOUT$`), independent of redirected stdin and stdout, read
/// as UTF-16 by rpassword (`ReadConsoleW`) so non-ASCII paths survive any console code page; the
/// typed characters are shown, not masked. rpassword drops Ctrl+Z; end of input is Ctrl+D on an
/// empty line, as on Unix, so the prompt says so.
#[cfg(all(windows, not(feature = "test-loopback")))]
fn tty_plain_line(label: &str) -> std::io::Result<String> {
    let config = rpassword::ConfigBuilder::new()
        .password_feedback_partial_mask('*', usize::MAX)
        .build();
    rpassword::prompt_password_with_config(format!("(Ctrl+D to stop) {label}"), config)
}

/// One line without the line ending; end of input is an error (the terminal is gone).
#[cfg(all(unix, not(feature = "test-loopback")))]
fn read_console_line(r: impl Read) -> std::io::Result<String> {
    use std::io::BufRead;
    let mut line = String::new();
    if std::io::BufReader::new(r).read_line(&mut line)? == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    Ok(line.trim_end_matches(['\n', '\r']).to_owned())
}

#[cfg(feature = "test-loopback")]
fn tty_plain_line(label: &str) -> std::io::Result<String> {
    tty_line(label)
}

#[cfg(feature = "test-loopback")]
fn tty_line(label: &str) -> std::io::Result<String> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let _ = write!(std::io::stderr(), "{label}");
    let path =
        std::env::var("SDROP_TEST_TTY_INPUT").map_err(|_| std::io::Error::other("no tty"))?;
    let text = std::fs::read_to_string(path)?;
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    text.lines()
        .nth(n)
        .map(str::to_owned)
        .ok_or_else(|| std::io::Error::other("no more tty input"))
}

fn json(body: &[u8]) -> Result<Value, CliError> {
    serde_json::from_slice(body)
        .map_err(|_| CliError::Msg("the server returned an unexpected answer".into()))
}

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str, CliError> {
    v.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Msg("the server returned an unexpected answer".into()))
}

pub struct PutArgs<'a> {
    pub ttl: &'a str,
    pub passphrase: bool,
    pub passphrase_file: Option<&'a Path>,
    /// Text from a file or stdin.
    pub input: Option<&'a Path>,
    /// Files as is (`--file`, repeatable): any bytes, the name is the path's base name.
    pub files: &'a [PathBuf],
}

/// File for `put --file`: bytes and the sanitized name.
fn read_file_secret(p: &Path) -> Result<(String, Zeroizing<Vec<u8>>), CliError> {
    let shown = api::printable(&p.display().to_string());
    let mut buf = Zeroizing::new(Vec::new());
    std::fs::File::open(p)
        .and_then(|f| f.take(MAX_INPUT + 1).read_to_end(&mut buf))
        .map_err(|_| CliError::Msg(format!("cannot read {shown}")))?;
    if buf.len() as u64 > MAX_INPUT {
        return Err(FormatError::TooLarge.into());
    }
    let raw = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok((format::sanitize_file_name(&raw), buf))
}

/// Service limit (`GET /api/limits`): one of the format buckets.
fn fetch_limit(
    agent: &ureq::Agent,
    origin: &Origin,
    creds: &mut Option<access::Credentials>,
) -> Result<usize, CliError> {
    let r = api::call_user(agent, origin, "GET", "/api/limits", creds, &[], None)?;
    if r.status != 200 {
        return Err(http_error("reading the service limit failed", r.status));
    }
    let v = json(&r.body)?;
    match v
        .get("maxBucket")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
    {
        Some(n) if format::BUCKETS.contains(&n) => Ok(n),
        _ => err("the server returned an unexpected answer"),
    }
}

fn human_size(n: usize) -> String {
    if n >= 1 << 20 {
        format!("{} MB", n >> 20)
    } else if n >= 1024 {
        format!("{} KB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// Recipient and sender links (stdout and stderr are handled in main).
pub fn put(a: PutArgs) -> Result<(String, String, String), CliError> {
    let origin = Origin::configured()?;
    let ttl = ttl_seconds(a.ttl)?;
    if a.files.len() > format::MAX_FILES {
        return Err(FormatError::TooManyFiles.into());
    }
    // With --file the text is taken only from an explicit INPUT (a path or "-" for stdin).
    let text = if a.files.is_empty() || a.input.is_some() {
        read_input(a.input)?
    } else {
        Zeroizing::new(String::new())
    };
    let files = a
        .files
        .iter()
        .map(|p| read_file_secret(p))
        .collect::<Result<Vec<_>, _>>()?;
    // One record per secret (FORMAT.md 4): text, file or text with files.
    let content = format::compose(
        &text,
        files.iter().map(|(n, d)| (n.as_str(), &d[..])).collect(),
    );
    format::encode_plaintext(&content, format::MAX_BUCKET)?;
    let passphrase = match (a.passphrase_file, a.passphrase) {
        (Some(p), _) => Some(read_passphrase_file(p)?),
        (None, true) => {
            let p = prompt("Passphrase: ")?;
            if *prompt("Repeat passphrase: ")? != *p {
                return err("the passphrases do not match");
            }
            Some(p)
        }
        (None, false) => None,
    };
    let mut creds = access::user_preset()?;
    let agent = api::agent();
    let limit = fetch_limit(&agent, &origin, &mut creds)?;
    let (envelope, k_url) =
        match format::encrypt(&content, passphrase.as_deref().map(String::as_str), limit) {
            Err(FormatError::TooLarge) => {
                return err(format!(
                    "the secret is larger than the service limit of {}",
                    human_size(limit)
                ));
            }
            r => r?,
        };
    let r = api::call_user(
        &agent,
        &origin,
        "POST",
        &format!("/api/secrets?ttl={ttl}"),
        &mut creds,
        &[("Content-Type", "application/octet-stream")],
        Some(&envelope),
    )?;
    if r.status == 413 {
        return err("the secret is larger than the service limit");
    }
    if r.status != 201 {
        return Err(http_error("creating the secret failed", r.status));
    }
    let v = json(&r.body)?;
    let id = field(&v, "id")?;
    let token = field(&v, "ownerToken")?;
    let expires = field(&v, "expiresAt")?;
    if id.len() != 64
        || !id.bytes().all(|b| b.is_ascii_hexdigit())
        || format::decode_key(token).is_err()
    {
        return err("the server returned an unexpected answer");
    }
    let suffix = if passphrase.is_some() {
        format::PASSPHRASE_SUFFIX
    } else {
        ""
    };
    Ok((
        format!(
            "{}/s/{id}#{}{suffix}",
            origin.as_str(),
            format::encode_base64url(&*k_url)
        ),
        format!("{}/o/{id}#{token}", origin.as_str()),
        api::printable(expires),
    ))
}

/// Link from the argument or from stdin ("-"), so the key does not end up in shell history.
pub fn link_arg(url: &str) -> Result<Zeroizing<String>, CliError> {
    if url != "-" {
        return Ok(Zeroizing::new(url.to_owned()));
    }
    let s = read_input(None)?;
    Ok(Zeroizing::new(s.trim().to_owned()))
}

/// Secret text. Passphrase: from a file, always before the request; from the terminal, before the
/// request on `~p`, after it on the envelope flag. Wrong passphrase retry: terminal only (up to 3).
pub fn get(url: &str, passphrase_file: Option<&Path>, out: Option<&Path>) -> Result<(), CliError> {
    let origin = Origin::configured()?;
    let link = api::parse_recipient_link(&origin, url)?;
    if let Some(p) = out.filter(|p| *p != Path::new("-")) {
        check_target(p)?;
    }
    let from_file = passphrase_file.map(read_passphrase_file).transpose()?;
    let interactive = from_file.is_none();
    let mut passphrase = match (&from_file, link.passphrase_hint) {
        (Some(p), _) => Some(p.clone()),
        (None, true) => Some(prompt("Passphrase: ")?),
        (None, false) => None,
    };
    let mut creds = access::user_preset()?;
    let r = api::call_user(
        &api::agent(),
        &origin,
        "POST",
        &format!("/api/secrets/{}/consume", link.id),
        &mut creds,
        &[],
        None,
    )
    .map_err(|e| match e {
        // Network dropped: consume may already have happened (FORMAT.md 6: at most one delivery).
        CliError::Network(m) => CliError::Msg(format!(
            "{m}. The result is unknown: the secret may already be destroyed on the server. \
             Try again; if it is then not found, ask the sender to send it again."
        )),
        other => other,
    })?;
    match r.status {
        200 => {}
        404 => {
            return err(
                "secret not found, already read, revoked or expired. If you didn't open it yourself, tell the sender.",
            );
        }
        s => return Err(http_error("fetching the secret failed", s)),
    }
    let envelope = Zeroizing::new(r.body);
    let mut wrong = 0;
    loop {
        match format::decrypt(
            &envelope,
            &link.key,
            passphrase.as_deref().map(String::as_str),
        ) {
            Ok(secret) => return deliver(secret, out, &link.id),
            Err(FormatError::NeedPassphrase) if interactive => {
                note!(
                    "This secret is protected with a passphrase. It is already deleted from the server; closing now destroys it."
                );
            }
            Err(FormatError::DecryptFailed) if passphrase.is_some() && interactive && wrong < 2 => {
                wrong += 1;
                note!(
                    "Wrong passphrase. The secret is already deleted from the server; try again."
                );
            }
            Err(FormatError::DecryptFailed) if passphrase.is_some() => {
                return err(
                    "wrong passphrase. The secret is already deleted from the server and cannot be fetched again.",
                );
            }
            Err(e) => return Err(e.into()),
        }
        passphrase = Some(prompt_after_burn()?);
    }
}

/// Passphrase after burning: on empty input ask again, no limit (the envelope exists only here).
/// Exit only if the terminal is closed (Ctrl-D) or unavailable.
fn prompt_after_burn() -> Result<Zeroizing<String>, CliError> {
    loop {
        let p = read_tty("Passphrase: ")?;
        if !p.is_empty() {
            return Ok(p);
        }
        note!("The passphrase is empty. Type it again (the secret is kept only in memory now).");
    }
}

/// `-o` path before consume: the parent is an existing directory, the path itself does not exist.
fn check_target(p: &Path) -> Result<(), CliError> {
    let shown = api::printable(&p.display().to_string());
    let parent = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    if !parent.is_dir() {
        return err(format!("{shown}: the directory does not exist"));
    }
    if std::fs::symlink_metadata(p).is_ok() {
        return err(format!("{shown} already exists; choose another path"));
    }
    Ok(())
}

/// New file with mode 0600; a partially written one is removed.
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path)?;
    if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// New private directory `sdrop-<id8>[-N]` (0700) and a `data` file in it.
fn save_default(id: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    for n in 0..100 {
        let dir = if n == 0 {
            PathBuf::from(format!("sdrop-{}", &id[..8]))
        } else {
            PathBuf::from(format!("sdrop-{}-{n}", &id[..8]))
        };
        match builder.create(&dir) {
            Ok(()) => {
                let file = dir.join("data");
                write_new(&file, bytes)?;
                return Ok(file);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
}

/// New private directory (0700) with the given files (0600). On any error everything written is
/// removed, so a retry starts clean.
fn write_dir(dir: &Path, entries: &[(String, &[u8])]) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)?;
    for (i, (name, bytes)) in entries.iter().enumerate() {
        if let Err(e) = write_new(&dir.join(name), bytes) {
            for (done, _) in &entries[..i] {
                let _ = std::fs::remove_file(dir.join(done));
            }
            let _ = std::fs::remove_dir(dir);
            return Err(e);
        }
    }
    Ok(())
}

/// New private directory `sdrop-<id8>[-N]` with the given files.
fn save_dir_default(id: &str, entries: &[(String, &[u8])]) -> std::io::Result<PathBuf> {
    for n in 0..100 {
        let dir = if n == 0 {
            PathBuf::from(format!("sdrop-{}", &id[..8]))
        } else {
            PathBuf::from(format!("sdrop-{}-{n}", &id[..8]))
        };
        match write_dir(&dir, entries) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
}

/// Text and files (README, FORMAT.md 4). Without `-o` or with `-o -`: the text to stdout, the files
/// to a new private directory as `file-N` (sender names are only shown). With `-o PATH`: a new
/// private directory PATH with `text` and `file-N`. A write error after consume keeps the secret:
/// another terminal path or the default directory, as for a single file.
fn deliver_bundle(
    text: &str,
    files: &[(String, Zeroizing<Vec<u8>>)],
    out: Option<&Path>,
    id: &str,
) -> Result<(), CliError> {
    let to_dir = matches!(out, Some(p) if p != Path::new("-"));
    let mut text_in_dir = to_dir;
    if !to_dir && !text.is_empty() {
        let mut o = std::io::stdout().lock();
        if o.write_all(text.as_bytes())
            .and_then(|_| o.flush())
            .is_err()
        {
            note!("Cannot write the text to the standard output; it is saved with the files.");
            text_in_dir = true;
        }
    }
    let mut entries: Vec<(String, &[u8])> = Vec::new();
    if text_in_dir && !text.is_empty() {
        entries.push(("text".into(), text.as_bytes()));
    }
    for (i, (_, data)) in files.iter().enumerate() {
        entries.push((format!("file-{}", i + 1), &data[..]));
    }
    let mut dest = match out {
        Some(p) if to_dir => Some(p.to_path_buf()),
        _ => None,
    };
    let mut tried_default = false;
    loop {
        let (shown, result) = match &dest {
            Some(p) => (
                api::printable(&p.display().to_string()),
                write_dir(p, &entries).map(|_| p.clone()),
            ),
            None => {
                tried_default = true;
                (
                    "the default directory".to_string(),
                    save_dir_default(id, &entries),
                )
            }
        };
        match result {
            Ok(dir) => {
                note!(
                    "Saved {} file(s) to {}:",
                    entries.len(),
                    api::printable(&dir.display().to_string())
                );
                if text_in_dir && !text.is_empty() {
                    note!("  text    ({})", human_size(text.len()));
                }
                for (i, (name, data)) in files.iter().enumerate() {
                    note!(
                        "  file-{}  ({}) the sender named it \"{}\"",
                        i + 1,
                        human_size(data.len()),
                        api::printable(name)
                    );
                }
                return Ok(());
            }
            Err(e) => note!(
                "Cannot write to {shown}: {}. The secret is kept in memory only now.",
                e.kind()
            ),
        }
        dest = loop {
            match tty_plain_line("Save to (new directory): ") {
                Ok(p) if p.trim().is_empty() => continue,
                Ok(p) => break Some(PathBuf::from(p.trim())),
                Err(_) if !tried_default => break None,
                Err(_) => {
                    return err("could not save the secret; it is already deleted from the server");
                }
            }
        };
    }
}

/// Output the decrypted secret: text to stdout, a file to a private directory; `-o` to the path.
/// A write error after consume keeps the secret: another terminal path or the default directory.
fn deliver(secret: Secret, out: Option<&Path>, id: &str) -> Result<(), CliError> {
    let (bytes, name): (&[u8], Option<&str>) = match &secret {
        Secret::Text(t) => (t.as_bytes(), None),
        Secret::File { name, data } => (data, Some(name.as_str())),
        Secret::Bundle { text, files } => return deliver_bundle(text, files, out, id),
    };
    /// Where to put the secret; any error leads to choosing another location, not to exiting.
    enum Dest {
        Stdout,
        Path(PathBuf),
        Default,
    }
    let mut dest = match out {
        Some(p) if p == Path::new("-") => Dest::Stdout,
        Some(p) => Dest::Path(p.to_path_buf()),
        None if name.is_none() => Dest::Stdout,
        None => Dest::Default,
    };
    let sender = name
        .map(|n| format!(" The sender named it \"{}\".", api::printable(n)))
        .unwrap_or_default();
    let mut tried_default = false;
    loop {
        let (shown, result) = match &dest {
            Dest::Stdout => {
                let mut o = std::io::stdout().lock();
                let r = o.write_all(bytes).and_then(|_| o.flush());
                if r.is_ok() {
                    return Ok(());
                }
                ("the standard output".to_string(), r.map(|_| PathBuf::new()))
            }
            Dest::Path(p) => (
                api::printable(&p.display().to_string()),
                write_new(p, bytes).map(|_| p.clone()),
            ),
            Dest::Default => {
                tried_default = true;
                ("the default directory".to_string(), save_default(id, bytes))
            }
        };
        match result {
            Ok(p) => {
                note!(
                    "Saved to {} ({}).{sender}",
                    api::printable(&p.display().to_string()),
                    human_size(bytes.len())
                );
                return Ok(());
            }
            Err(e) => note!(
                "Cannot write to {shown}: {}. The secret is kept in memory only now.",
                e.kind()
            ),
        }
        dest = loop {
            match tty_plain_line("Save to (path): ") {
                Ok(p) if p.trim().is_empty() => continue,
                Ok(p) => break Dest::Path(PathBuf::from(p.trim())),
                Err(_) if !tried_default => break Dest::Default,
                Err(_) => {
                    return err("could not save the secret; it is already deleted from the server");
                }
            }
        };
    }
}

fn status_text(v: &Value) -> Result<String, CliError> {
    let mut out = format!(
        "state:   {}\ncreated: {}\nexpires: {}\n",
        api::printable(field(v, "state")?),
        api::printable(field(v, "createdAt")?),
        api::printable(field(v, "expiresAt")?)
    );
    if let Some(at) = v.get("consumedAt").and_then(Value::as_str) {
        // In public mode there is no name: time only.
        match v.get("consumedBy").and_then(Value::as_str) {
            Some(by) => out.push_str(&format!(
                "read:    {} by {}\n",
                api::printable(at),
                api::printable(by)
            )),
            None => out.push_str(&format!("read:    {}\n", api::printable(at))),
        }
    }
    Ok(out)
}

pub fn status(url: &str) -> Result<String, CliError> {
    let origin = Origin::configured()?;
    let link = api::parse_owner_link(&origin, url)?;
    let mut creds = access::user_preset()?;
    let auth = Zeroizing::new(format!("Bearer {}", link.token.as_str()));
    let r = api::call_user(
        &api::agent(),
        &origin,
        "GET",
        &format!("/api/secrets/{}/status", link.id),
        &mut creds,
        &[("Authorization", &auth)],
        None,
    )?;
    match r.status {
        200 => status_text(&json(&r.body)?),
        404 => err("secret not found or expired"),
        s => Err(http_error("fetching the status failed", s)),
    }
}

pub fn revoke(url: &str) -> Result<String, CliError> {
    let origin = Origin::configured()?;
    let link = api::parse_owner_link(&origin, url)?;
    let mut creds = access::user_preset()?;
    let auth = Zeroizing::new(format!("Bearer {}", link.token.as_str()));
    let r = api::call_user(
        &api::agent(),
        &origin,
        "DELETE",
        &format!("/api/secrets/{}", link.id),
        &mut creds,
        &[("Authorization", &auth)],
        None,
    )?;
    match r.status {
        204 => Ok("revoked\n".into()),
        409 => err(format!(
            "already read, cannot revoke:\n{}",
            status_text(&json(&r.body)?)?
        )),
        404 => err("secret not found or expired"),
        s => Err(http_error("revoking failed", s)),
    }
}

pub fn write_stdout(s: &str) -> Result<(), CliError> {
    let mut out = std::io::stdout().lock();
    out.write_all(s.as_bytes())
        .and_then(|_| out.flush())
        .map_err(|_| CliError::Msg("cannot write the output".into()))
}
