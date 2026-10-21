//! Envelope format v1 and v2 (FORMAT.md), the same as the browser client.
//! Error codes match the browser client: the shared vectors spec/*.json check both implementations.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub const MAGIC: [u8; 4] = *b"SDRP";
pub const VERSION: u8 = 1;
/// Envelope version of a text and several files (kind "bundle", FORMAT.md 4).
pub const VERSION_BUNDLE: u8 = 2;
pub const MAX_FILES: usize = 20;
pub const FLAG_PASSPHRASE: u8 = 1;
pub const HEADER_LEN: usize = 34;
pub const SALT_LEN: usize = 16;
pub const IV_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const BUCKETS: [usize; 6] = [1024, 4096, 16384, 65536, 262144, 1048576];
pub const MAX_BUCKET: usize = 1048576;
pub const PBKDF2_ITERATIONS: u32 = 600_000;
pub const HKDF_INFO: &[u8] = b"secret-drop v1 aes-256-gcm";
pub const PASSPHRASE_SUFFIX: &str = "~p";
const TEXT_PREFIX: &str = r#"{"kind":"text","text":"#;
const FILE_PREFIX: &str = r#"{"kind":"file","name":"#;
const SIZE_KEY: &str = r#","size":"#;

/// Format error; `code()` uses the same dictionary as JS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    BadLink,
    EmptyText,
    EmptyFile,
    BadName,
    TooLarge,
    TooManyFiles,
    EmptyPassphrase,
    Corrupt,
    NeedPassphrase,
    DecryptFailed,
}

impl FormatError {
    pub fn code(self) -> &'static str {
        match self {
            Self::BadLink => "bad_link",
            Self::EmptyText => "empty_text",
            Self::EmptyFile => "empty_file",
            Self::BadName => "bad_name",
            Self::TooLarge => "too_large",
            Self::TooManyFiles => "too_many_files",
            Self::EmptyPassphrase => "empty_passphrase",
            Self::Corrupt => "corrupt",
            Self::NeedPassphrase => "need_passphrase",
            Self::DecryptFailed => "decrypt_failed",
        }
    }
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for FormatError {}

pub type Key = Zeroizing<[u8; KEY_LEN]>;

pub fn envelope_lengths() -> [usize; 6] {
    BUCKETS.map(|b| HEADER_LEN + b + TAG_LEN)
}

pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict decoding into exactly 32 bytes: base64url alphabet only, no padding,
/// re-encoding matches the input.
pub fn decode_key(s: &str) -> Result<Key, FormatError> {
    if s.len() != 43 {
        return Err(FormatError::BadLink);
    }
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| FormatError::BadLink)?,
    );
    if bytes.len() != KEY_LEN || encode_base64url(&bytes) != s {
        return Err(FormatError::BadLink);
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Recipient link fragment: the key and the `~p` flag.
pub fn parse_recipient_fragment(fragment: &str) -> Result<(Key, bool), FormatError> {
    match fragment.strip_suffix(PASSPHRASE_SUFFIX) {
        Some(body) => Ok((decode_key(body)?, true)),
        None => Ok((decode_key(fragment)?, false)),
    }
}

/// Sender link fragment: ownerToken (32 bytes base64url), returned as is.
pub fn parse_owner_fragment(fragment: &str) -> Result<Zeroizing<String>, FormatError> {
    decode_key(fragment)?;
    Ok(Zeroizing::new(fragment.to_owned()))
}

/// Secret to encrypt (FORMAT.md 3, 4).
pub enum Content<'a> {
    Text(&'a str),
    File {
        name: &'a str,
        data: &'a [u8],
    },
    Bundle {
        text: &'a str,
        files: Vec<(&'a str, &'a [u8])>,
    },
}

/// Decrypted secret.
#[derive(Debug, PartialEq, Eq)]
pub enum Secret {
    Text(Zeroizing<String>),
    File {
        name: String,
        data: Zeroizing<Vec<u8>>,
    },
    Bundle {
        text: Zeroizing<String>,
        files: Vec<(String, Zeroizing<Vec<u8>>)>,
    },
}

/// The one record for a text and files (FORMAT.md 4): no files - text, one file and no text -
/// file, otherwise bundle.
pub fn compose<'a>(text: &'a str, mut files: Vec<(&'a str, &'a [u8])>) -> Content<'a> {
    match files.len() {
        0 => Content::Text(text),
        1 if text.is_empty() => {
            let (name, data) = files.remove(0);
            Content::File { name, data }
        }
        _ => Content::Bundle { text, files },
    }
}

/// Envelope version of a secret: bundle - 2, otherwise 1.
pub fn version_of(content: &Content) -> u8 {
    match content {
        Content::Bundle { .. } => VERSION_BUNDLE,
        _ => VERSION,
    }
}

/// File name per FORMAT.md 3: 1-255 bytes of UTF-8, no control characters, `/`, `\`, not `.`/`..`.
pub fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c < '\u{20}' || c == '\u{7f}' || c == '/' || c == '\\')
}

/// Name to send: base name, control characters -> `_`, at most 255 bytes.
pub fn sanitize_file_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let mut name: String = base
        .chars()
        .map(|c| {
            if c < '\u{20}' || c == '\u{7f}' {
                '_'
            } else {
                c
            }
        })
        .collect();
    while name.len() > 255 {
        name.pop();
    }
    if name.is_empty() || name == "." || name == ".." {
        "file".into()
    } else {
        name
    }
}

fn bucket_for(need: usize, max_bucket: usize) -> Result<usize, FormatError> {
    BUCKETS
        .iter()
        .copied()
        .find(|b| *b >= need)
        .filter(|b| *b <= max_bucket)
        .ok_or(FormatError::TooLarge)
}

/// Canonical plaintext encoding padded to the bucket (FORMAT.md 3).
pub fn encode_plaintext(
    content: &Content,
    max_bucket: usize,
) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    let joined: Zeroizing<Vec<u8>>;
    let (header, data): (Zeroizing<String>, &[u8]) = match content {
        Content::Text(text) => {
            if text.is_empty() {
                return Err(FormatError::EmptyText);
            }
            // Written into a preallocated buffer: no reallocation leaves copies of the text.
            let mut h = Zeroizing::new(String::with_capacity(
                TEXT_PREFIX.len() + json_string_len(text) + 1,
            ));
            h.push_str(TEXT_PREFIX);
            push_json_string(&mut h, text);
            h.push('}');
            (h, &[])
        }
        Content::File { name, data } => {
            if !valid_file_name(name) {
                return Err(FormatError::BadName);
            }
            if data.is_empty() {
                return Err(FormatError::EmptyFile);
            }
            let lit = serde_json::to_string(name).map_err(|_| FormatError::BadName)?;
            (
                Zeroizing::new(format!("{FILE_PREFIX}{lit}{SIZE_KEY}{}}}", data.len())),
                *data,
            )
        }
        Content::Bundle { text, files } => {
            if files.len() > MAX_FILES {
                return Err(FormatError::TooManyFiles);
            }
            // Only the one record (FORMAT.md 4): fewer parts are text or file kinds.
            if files.is_empty() || (files.len() == 1 && text.is_empty()) {
                return Err(FormatError::Corrupt);
            }
            for (name, data) in files {
                if !valid_file_name(name) {
                    return Err(FormatError::BadName);
                }
                if data.is_empty() {
                    return Err(FormatError::EmptyFile);
                }
            }
            let sizes: Vec<(&str, usize)> = files.iter().map(|(n, d)| (*n, d.len())).collect();
            joined = Zeroizing::new(files.iter().flat_map(|(_, d)| d.iter().copied()).collect());
            (bundle_header(text, &sizes)?, &joined[..])
        }
    };
    let bucket = bucket_for(4 + header.len() + data.len(), max_bucket)?;
    let mut out = Zeroizing::new(vec![0u8; bucket]);
    out[..4].copy_from_slice(&(header.len() as u32).to_be_bytes());
    out[4..4 + header.len()].copy_from_slice(header.as_bytes());
    out[4 + header.len()..4 + header.len() + data.len()].copy_from_slice(data);
    Ok(out)
}

const BUNDLE_PREFIX: &str = r#"{"kind":"bundle","text":"#;
const FILES_KEY: &str = r#","files":"#;

/// Length of the canonical JSON string literal of `s` (FORMAT.md 3, 4).
fn json_string_len(s: &str) -> usize {
    2 + s
        .chars()
        .map(|c| match c {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
            c if c < '\u{20}' => 6,
            c => c.len_utf8(),
        })
        .sum::<usize>()
}

/// Canonical JSON string literal (FORMAT.md 3: as JSON.stringify and serde_json), written into
/// `out` without growing it when the capacity was reserved with `json_string_len`.
fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\u{20}' => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push_str("\\u00");
                out.push(HEX[(c as usize) >> 4] as char);
                out.push(HEX[(c as usize) & 15] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Canonical JSON string literal -> string, decoded straight into a wiped buffer (no parser
/// scratch copies). Only the forms `push_json_string` writes are accepted: any other escape,
/// a raw control character or a raw quote is corrupt.
fn decode_json_literal(lit: &str) -> Result<Zeroizing<String>, FormatError> {
    let inner = lit
        .strip_prefix('"')
        .and_then(|l| l.strip_suffix('"'))
        .ok_or(FormatError::Corrupt)?;
    let mut out = Zeroizing::new(String::with_capacity(inner.len()));
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Err(FormatError::Corrupt),
            c if c < '\u{20}' => return Err(FormatError::Corrupt),
            '\\' => {
                let e = match chars.next() {
                    Some('"') => '"',
                    Some('\\') => '\\',
                    Some('b') => '\u{8}',
                    Some('f') => '\u{c}',
                    Some('n') => '\n',
                    Some('r') => '\r',
                    Some('t') => '\t',
                    Some('u') => {
                        let mut v = 0u32;
                        for _ in 0..4 {
                            let d = match chars.next() {
                                Some(d @ '0'..='9') => d as u32 - '0' as u32,
                                Some(d @ 'a'..='f') => d as u32 - 'a' as u32 + 10,
                                _ => return Err(FormatError::Corrupt),
                            };
                            v = v * 16 + d;
                        }
                        // \u00xx only for control characters without a short form.
                        if v >= 0x20 || matches!(v, 0x8 | 0x9 | 0xa | 0xc | 0xd) {
                            return Err(FormatError::Corrupt);
                        }
                        char::from_u32(v).ok_or(FormatError::Corrupt)?
                    }
                    _ => return Err(FormatError::Corrupt),
                };
                out.push(e);
            }
            c => out.push(c),
        }
    }
    Ok(out)
}

/// Canonical bundle header (FORMAT.md 4), in a preallocated wiped buffer.
fn bundle_header(text: &str, files: &[(&str, usize)]) -> Result<Zeroizing<String>, FormatError> {
    let list: Vec<String> = files
        .iter()
        .map(|(name, size)| {
            let mut e = String::with_capacity(json_string_len(name) + 32);
            e.push_str(r#"{"name":"#);
            push_json_string(&mut e, name);
            e.push_str(&format!(r#","size":{size}}}"#));
            e
        })
        .collect();
    let cap = BUNDLE_PREFIX.len()
        + json_string_len(text)
        + FILES_KEY.len()
        + list.iter().map(|e| e.len() + 1).sum::<usize>()
        + 3;
    let mut out = Zeroizing::new(String::with_capacity(cap));
    out.push_str(BUNDLE_PREFIX);
    push_json_string(&mut out, text);
    out.push_str(FILES_KEY);
    out.push('[');
    out.push_str(&list.join(","));
    out.push_str("]}");
    Ok(out)
}

/// Bundle header: the text and the file names with sizes.
type BundleHeader = (Zeroizing<String>, Vec<(String, usize)>);

/// Bundle header (FORMAT.md 4). The text literal is decoded by `decode_json_literal` (wiped
/// buffer, canonical forms only); the file list by serde_json. The header is accepted only if its
/// canonical rewrite gives the same string.
fn parse_bundle_header(s: &str) -> Result<BundleHeader, FormatError> {
    let rest = s.strip_prefix(BUNDLE_PREFIX).ok_or(FormatError::Corrupt)?;
    // End of the text literal: the first unescaped quote after the opening one.
    let bytes = rest.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err(FormatError::Corrupt);
    }
    let mut i = 1;
    let close = loop {
        match bytes.get(i) {
            Some(b'\\') => i += 2,
            Some(b'"') => break i,
            Some(_) => i += 1,
            None => return Err(FormatError::Corrupt),
        }
    };
    let text = decode_json_literal(&rest[..=close])?;
    let list_json = rest[close + 1..]
        .strip_prefix(FILES_KEY)
        .and_then(|l| l.strip_suffix('}'))
        .ok_or(FormatError::Corrupt)?;
    let v: serde_json::Value = serde_json::from_str(list_json).map_err(|_| FormatError::Corrupt)?;
    let list = v.as_array().ok_or(FormatError::Corrupt)?;
    if list.is_empty() || list.len() > MAX_FILES || (list.len() == 1 && text.is_empty()) {
        return Err(FormatError::Corrupt);
    }
    let mut files = Vec::with_capacity(list.len());
    for f in list {
        let f = f.as_object().ok_or(FormatError::Corrupt)?;
        let name = f
            .get("name")
            .and_then(|n| n.as_str())
            .filter(|n| valid_file_name(n))
            .ok_or(FormatError::Corrupt)?;
        let size = f
            .get("size")
            .and_then(|n| n.as_u64())
            .filter(|n| *n >= 1)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(FormatError::Corrupt)?;
        files.push((name.to_owned(), size));
    }
    let refs: Vec<(&str, usize)> = files.iter().map(|(n, z)| (n.as_str(), *z)).collect();
    if *bundle_header(&text, &refs)? != s {
        return Err(FormatError::Corrupt);
    }
    Ok((text, files))
}

/// JSON string in canonical form -> non-empty string.
fn canonical_string(literal: &str) -> Result<Zeroizing<String>, FormatError> {
    let v = decode_json_literal(literal)?;
    if v.is_empty() {
        return Err(FormatError::Corrupt);
    }
    Ok(v)
}

/// Parse the plaintext: canonical header encoding only, zero tail, minimal bucket (FORMAT.md 3).
/// Version 1 holds text or file, version 2 only bundle (FORMAT.md 4).
pub fn decode_plaintext(plain: &[u8], version: u8) -> Result<Secret, FormatError> {
    if !BUCKETS.contains(&plain.len()) {
        return Err(FormatError::Corrupt);
    }
    let len = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
    if len > plain.len() - 4 {
        return Err(FormatError::Corrupt);
    }
    let s = std::str::from_utf8(&plain[4..4 + len]).map_err(|_| FormatError::Corrupt)?;
    let body = s.strip_suffix('}').ok_or(FormatError::Corrupt)?;
    let mut end = 4 + len;
    let secret = if version == VERSION_BUNDLE {
        let (text, list) = parse_bundle_header(s)?;
        let total = list
            .iter()
            .try_fold(0usize, |n, (_, z)| n.checked_add(*z))
            .ok_or(FormatError::Corrupt)?;
        if total > plain.len() - end {
            return Err(FormatError::Corrupt);
        }
        let mut files = Vec::with_capacity(list.len());
        for (name, size) in list {
            files.push((name, Zeroizing::new(plain[end..end + size].to_vec())));
            end += size;
        }
        Secret::Bundle { text, files }
    } else if version != VERSION {
        return Err(FormatError::Corrupt);
    } else if let Some(lit) = body.strip_prefix(TEXT_PREFIX) {
        Secret::Text(canonical_string(lit)?)
    } else if let Some(rest) = body.strip_prefix(FILE_PREFIX) {
        let at = rest.rfind(SIZE_KEY).ok_or(FormatError::Corrupt)?;
        let digits = &rest[at + SIZE_KEY.len()..];
        let ok_digits = (1..=8).contains(&digits.len())
            && digits.bytes().all(|b| b.is_ascii_digit())
            && !digits.starts_with('0');
        if !ok_digits {
            return Err(FormatError::Corrupt);
        }
        let name = canonical_string(&rest[..at])?;
        if !valid_file_name(&name) {
            return Err(FormatError::Corrupt);
        }
        let size: usize = digits.parse().map_err(|_| FormatError::Corrupt)?;
        if 4 + len + size > plain.len() {
            return Err(FormatError::Corrupt);
        }
        let data = Zeroizing::new(plain[end..end + size].to_vec());
        end += size;
        Secret::File {
            name: name.to_string(),
            data,
        }
    } else {
        return Err(FormatError::Corrupt);
    };
    if plain[end..].iter().any(|b| *b != 0) {
        return Err(FormatError::Corrupt);
    }
    // Only the minimal bucket (FORMAT.md 3): the same content in a larger bucket is another record.
    if BUCKETS.iter().copied().find(|b| *b >= end) != Some(plain.len()) {
        return Err(FormatError::Corrupt);
    }
    Ok(secret)
}

fn passphrase_bytes(passphrase: &str) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    if passphrase.is_empty() {
        return Err(FormatError::EmptyPassphrase);
    }
    Ok(Zeroizing::new(
        passphrase.nfc().collect::<String>().into_bytes(),
    ))
}

/// K_enc per FORMAT.md 1.
pub fn derive_key(
    k_url: &[u8; KEY_LEN],
    salt: &[u8],
    passphrase: Option<&str>,
) -> Result<Key, FormatError> {
    let mut ikm = Zeroizing::new(k_url.to_vec());
    if let Some(p) = passphrase {
        let pw = passphrase_bytes(p)?;
        let mut derived = Zeroizing::new([0u8; KEY_LEN]);
        pbkdf2::pbkdf2_hmac::<Sha256>(&pw, salt, PBKDF2_ITERATIONS, &mut *derived);
        ikm.extend_from_slice(&*derived);
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(salt), &ikm)
        .expand(HKDF_INFO, &mut *out)
        .map_err(|_| FormatError::Corrupt)?;
    Ok(out)
}

fn header(version: u8, flags: u8, salt: &[u8; SALT_LEN], iv: &[u8; IV_LEN]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(&MAGIC);
    h[4] = version;
    h[5] = flags;
    h[6..22].copy_from_slice(salt);
    h[22..34].copy_from_slice(iv);
    h
}

/// Seal a ready plaintext with the given random values and envelope version.
pub fn seal(
    plain: &[u8],
    k_url: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    iv: &[u8; IV_LEN],
    passphrase: Option<&str>,
    version: u8,
) -> Result<Vec<u8>, FormatError> {
    let h = header(
        version,
        if passphrase.is_some() {
            FLAG_PASSPHRASE
        } else {
            0
        },
        salt,
        iv,
    );
    let key = derive_key(k_url, salt, passphrase)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| FormatError::Corrupt)?;
    let nonce = Nonce::try_from(&iv[..]).map_err(|_| FormatError::Corrupt)?;
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plain,
                aad: &h,
            },
        )
        .map_err(|_| FormatError::Corrupt)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(&h);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn encrypt_with(
    content: &Content,
    k_url: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    iv: &[u8; IV_LEN],
    passphrase: Option<&str>,
    max_bucket: usize,
) -> Result<Vec<u8>, FormatError> {
    if let Some(p) = passphrase {
        passphrase_bytes(p)?;
    }
    seal(
        &encode_plaintext(content, max_bucket)?,
        k_url,
        salt,
        iv,
        passphrase,
        version_of(content),
    )
}

/// Encrypt a secret with fresh random values: the envelope and K_url.
pub fn encrypt(
    content: &Content,
    passphrase: Option<&str>,
    max_bucket: usize,
) -> Result<(Vec<u8>, Key), FormatError> {
    let mut k_url = Zeroizing::new([0u8; KEY_LEN]);
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    for buf in [&mut k_url[..], &mut salt[..], &mut iv[..]] {
        getrandom::fill(buf).expect("system random number generator is unavailable");
    }
    Ok((
        encrypt_with(content, &k_url, &salt, &iv, passphrase, max_bucket)?,
        k_url,
    ))
}

/// Header and length check without the key; true means the envelope has a passphrase.
pub fn inspect_envelope(env: &[u8]) -> Result<bool, FormatError> {
    if !envelope_lengths().contains(&env.len()) || env[..4] != MAGIC {
        return Err(FormatError::Corrupt);
    }
    if (env[4] != VERSION && env[4] != VERSION_BUNDLE) || env[5] & !FLAG_PASSPHRASE != 0 {
        return Err(FormatError::Corrupt);
    }
    Ok(env[5] & FLAG_PASSPHRASE != 0)
}

/// Decrypt an envelope. Passphrase needed but absent: `NeedPassphrase`; wrong passphrase or key:
/// `DecryptFailed`. A passphrase given for an envelope without the flag is not used (FORMAT.md 5).
pub fn decrypt(
    env: &[u8],
    k_url: &[u8; KEY_LEN],
    passphrase: Option<&str>,
) -> Result<Secret, FormatError> {
    let has_passphrase = inspect_envelope(env)?;
    if has_passphrase && passphrase.is_none() {
        return Err(FormatError::NeedPassphrase);
    }
    let key = derive_key(
        k_url,
        &env[6..22],
        if has_passphrase { passphrase } else { None },
    )?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| FormatError::Corrupt)?;
    let nonce = Nonce::try_from(&env[22..34]).map_err(|_| FormatError::Corrupt)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &env[HEADER_LEN..],
                    aad: &env[..HEADER_LEN],
                },
            )
            .map_err(|_| FormatError::DecryptFailed)?,
    );
    decode_plaintext(&plain, env[4])
}
