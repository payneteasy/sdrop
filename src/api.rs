//! Trusted origin, link parsing and the HTTP API (FORMAT.md 6, README). Requests go only to the trusted
//! origin, without redirects; the link is fully validated before any network request.

use crate::access::Credentials;
use crate::format::{self, FormatError, Key};
use std::time::Duration;
use zeroize::Zeroizing;

/// Largest API response: the 1048576 bucket envelope (FORMAT.md 2).
pub const MAX_RESPONSE: u64 = 1_048_626;

#[derive(Debug)]
pub enum CliError {
    /// Human-readable message; contains no secrets, keys or tokens.
    Msg(String),
    /// Redirect response: Access requires login, the request never reached the service.
    Redirect(u16),
    /// Network or response-read failure: unknown whether the request reached the server.
    Network(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Msg(m) | CliError::Network(m) => f.write_str(m),
            CliError::Redirect(status) => write!(
                f,
                "the server answered with a redirect (HTTP {status}): Cloudflare Access login is required or the token has expired"
            ),
        }
    }
}

pub fn err<T>(m: impl Into<String>) -> Result<T, CliError> {
    Err(CliError::Msg(m.into()))
}

impl From<FormatError> for CliError {
    fn from(e: FormatError) -> Self {
        CliError::Msg(match e {
            FormatError::BadLink => "the link is broken or incomplete".into(),
            FormatError::EmptyText => "the secret is empty".into(),
            FormatError::EmptyFile => "the file is empty".into(),
            FormatError::BadName => "the file name is not allowed".into(),
            FormatError::TooLarge => "the secret is larger than the service limit".into(),
            FormatError::TooManyFiles => {
                format!("too many files: at most {}", crate::format::MAX_FILES)
            }
            FormatError::EmptyPassphrase => "the passphrase is empty".into(),
            FormatError::Corrupt => "the secret is damaged and cannot be shown".into(),
            FormatError::NeedPassphrase => "a passphrase is required".into(),
            FormatError::DecryptFailed => {
                "could not decrypt: wrong passphrase or damaged link".into()
            }
        })
    }
}

/// Trusted origin: `https://host[:port]`; `test-loopback` build also `http://127.0.0.1:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin(String);

impl Origin {
    pub fn parse(s: &str) -> Result<Origin, CliError> {
        let bad = || err(format!("not an allowed origin: {}", printable(s)));
        let (scheme, rest) = match s.split_once("://") {
            Some(p) => p,
            None => return bad(),
        };
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p))
                if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) =>
            {
                (h, Some(p))
            }
            _ => (rest, None),
        };
        let host_ok = !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && l.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            });
        if !host_ok {
            return bad();
        }
        match scheme {
            "https" => Ok(Origin(s.to_owned())),
            "http" if cfg!(feature = "test-loopback") && host == "127.0.0.1" && port.is_some() => {
                Ok(Origin(s.to_owned()))
            }
            _ => bad(),
        }
    }

    /// `SDROP_ORIGIN` or `SDROP_DEFAULT_ORIGIN` baked in at build time.
    pub fn configured() -> Result<Origin, CliError> {
        let v = std::env::var("SDROP_ORIGIN").ok().filter(|v| !v.is_empty());
        let v = v.unwrap_or_else(|| env!("SDROP_DEFAULT_ORIGIN").to_owned());
        if v.is_empty() {
            return err(
                "no server configured: set SDROP_ORIGIN (e.g. https://secrets.example.com)",
            );
        }
        Origin::parse(&v)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Replace characters unsafe for a terminal; truncate anything long.
pub fn printable(s: &str) -> String {
    s.chars()
        .take(80)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// `{origin}/{kind}/{id}#{fragment}`: exact origin match, id is 64 lowercase hex.
fn split_link<'a>(
    origin: &Origin,
    url: &'a str,
    kind: char,
) -> Result<(&'a str, &'a str), CliError> {
    let rest = url
        .strip_prefix(origin.as_str())
        .and_then(|r| r.strip_prefix('/'))
        .and_then(|r| r.strip_prefix(kind))
        .and_then(|r| r.strip_prefix('/'));
    let Some(rest) = rest else {
        return err(format!("the link is not for {}", origin.as_str()));
    };
    let (id, fragment) = rest.split_once('#').ok_or(FormatError::BadLink)?;
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(FormatError::BadLink.into());
    }
    Ok((id, fragment))
}

pub struct RecipientLink {
    pub id: String,
    pub key: Key,
    pub passphrase_hint: bool,
}

pub fn parse_recipient_link(origin: &Origin, url: &str) -> Result<RecipientLink, CliError> {
    let (id, fragment) = split_link(origin, url, 's')?;
    let (key, passphrase_hint) = format::parse_recipient_fragment(fragment)?;
    Ok(RecipientLink {
        id: id.to_owned(),
        key,
        passphrase_hint,
    })
}

pub struct OwnerLink {
    pub id: String,
    pub token: Zeroizing<String>,
}

pub fn parse_owner_link(origin: &Origin, url: &str) -> Result<OwnerLink, CliError> {
    let (id, fragment) = split_link(origin, url, 'o')?;
    Ok(OwnerLink {
        id: id.to_owned(),
        token: format::parse_owner_fragment(fragment)?,
    })
}

pub fn agent() -> ureq::Agent {
    let mut cfg = ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(60)))
        .user_agent(concat!("sdrop/", env!("CARGO_PKG_VERSION")));
    if cfg!(feature = "test-loopback") {
        cfg = cfg.proxy(None);
    }
    cfg.build().into()
}

pub struct Reply {
    pub status: u16,
    /// Names are lowercase; non-UTF-8 values are skipped.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// API request to the trusted origin with the `X-Secret-Drop` marker. A redirect is an error
/// (it is Access without login), not followed.
pub fn call(
    agent: &ureq::Agent,
    origin: &Origin,
    method: &str,
    path: &str,
    creds: Option<&Credentials>,
    extra: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<Reply, CliError> {
    let url = format!("{}{}", origin.as_str(), path);
    let mut req = ureq::http::Request::builder()
        .method(method)
        .uri(&url)
        .header("X-Secret-Drop", "1");
    for (k, v) in creds.map(Credentials::headers).unwrap_or_default() {
        req = req.header(k, v.as_str());
    }
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let req = req
        .body(body.map(|b| b.to_vec()).unwrap_or_default())
        .map_err(|_| CliError::Msg("bad request".into()))?;
    let mut res = agent.run(req).map_err(|e| {
        CliError::Network(format!(
            "request to {} failed: {}",
            origin.as_str(),
            error_kind(&e)
        ))
    })?;
    let status = res.status().as_u16();
    if (300..400).contains(&status) {
        return Err(CliError::Redirect(status));
    }
    let headers = res
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_ascii_lowercase(), v.to_owned()))
        })
        .collect();
    let body = res
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE)
        .read_to_vec()
        .map_err(|e| {
            CliError::Network(format!("reading the response failed: {}", error_kind(&e)))
        })?;
    Ok(Reply {
        status,
        headers,
        body,
    })
}

/// User request: first with the explicit token or without one; on an Access redirect without a
/// token, obtain a token and retry once (the request never reached the service, nothing burned).
#[allow(clippy::too_many_arguments)]
pub fn call_user(
    agent: &ureq::Agent,
    origin: &Origin,
    method: &str,
    path: &str,
    creds: &mut Option<Credentials>,
    extra: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<Reply, CliError> {
    match call(agent, origin, method, path, creds.as_ref(), extra, body) {
        Err(CliError::Redirect(_)) if creds.is_none() => {
            *creds = Some(crate::access::user_login(origin)?);
            call(agent, origin, method, path, creds.as_ref(), extra, body)
        }
        r => r,
    }
}

/// ureq error class without details (they may contain the URL).
fn error_kind(e: &ureq::Error) -> &'static str {
    match e {
        ureq::Error::Timeout(_) => "timeout",
        ureq::Error::Io(_) => "network error",
        ureq::Error::HostNotFound => "host not found",
        ureq::Error::ConnectionFailed => "connection failed",
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => "TLS error",
        ureq::Error::BodyExceedsLimit(_) => "response too large",
        _ => "HTTP error",
    }
}

pub fn http_error(what: &str, status: u16) -> CliError {
    match status {
        401 => CliError::Msg(format!(
            "{what}: not authorized by Cloudflare Access (HTTP 401)"
        )),
        403 => CliError::Msg(format!("{what}: forbidden (HTTP 403)")),
        429 => CliError::Msg(format!(
            "{what}: too many secrets created, wait a minute (HTTP 429)"
        )),
        s => CliError::Msg(format!("{what}: unexpected answer (HTTP {s})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_rules() {
        for ok in [
            "https://secrets.example.com",
            "https://a.b:8443",
            "https://localhost",
        ] {
            assert!(Origin::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "https://",
            "https://A.com",
            "https://a.com/",
            "https://a.com/x",
            "https://a..com",
            "https://a.com:",
            "https://user@a.com",
            "a.com",
            "https:/a.com",
        ] {
            assert!(Origin::parse(bad).is_err(), "{bad}");
        }
        // http only in the test build and only 127.0.0.1 with a port.
        assert_eq!(
            Origin::parse("http://127.0.0.1:8788").is_ok(),
            cfg!(feature = "test-loopback")
        );
        for bad in [
            "http://localhost:8788",
            "http://127.0.0.1",
            "http://10.0.0.1:80",
            "http://example.com:80",
        ] {
            assert!(Origin::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn links_must_match_origin_exactly() {
        let o = Origin::parse("https://s.example.com").unwrap();
        let key = "A".repeat(43);
        let id = "a".repeat(64);
        assert!(parse_recipient_link(&o, &format!("https://s.example.com/s/{id}#{key}")).is_ok());
        for bad in [
            format!("https://s.example.com.evil.com/s/{id}#{key}"),
            format!("https://s.example.com:443/s/{id}#{key}"),
            format!("http://s.example.com/s/{id}#{key}"),
            format!("https://s.example.com/s/{id}?x#{key}"),
            format!("https://s.example.com//s/{id}#{key}"),
        ] {
            assert!(parse_recipient_link(&o, &bad).is_err(), "{bad}");
        }
    }
}
