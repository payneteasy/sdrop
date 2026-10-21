//! Cloudflare Access login (README): the `cf-access-token` token from SDROP_ACCESS_TOKEN or from
//! `cloudflared`. In the `test-loopback` build only SDROP_TEST_*: real tokens are not read,
//! cloudflared is not invoked.

use crate::api::{CliError, Origin, err};
use zeroize::Zeroizing;

pub enum Credentials {
    User(Zeroizing<String>),
}

impl Credentials {
    pub fn headers(&self) -> Vec<(&'static str, Zeroizing<String>)> {
        match self {
            Credentials::User(t) => vec![("cf-access-token", t.clone())],
        }
    }
}

fn env_secret(name: &str) -> Option<Zeroizing<String>> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .map(Zeroizing::new)
}

/// Header value without control characters or spaces.
fn header_safe(v: &Zeroizing<String>) -> bool {
    !v.is_empty() && v.len() <= 8192 && v.bytes().all(|b| b.is_ascii_graphic())
}

fn checked(c: Credentials) -> Result<Credentials, CliError> {
    if c.headers().iter().all(|(_, v)| header_safe(v)) {
        Ok(c)
    } else {
        err("the Access token contains invalid characters")
    }
}

/// User token given explicitly (SDROP_ACCESS_TOKEN; in the test build,
/// SDROP_TEST_ACCESS_TOKEN). None: the request goes without a token (a service without login).
pub fn user_preset() -> Result<Option<Credentials>, CliError> {
    let var = if cfg!(feature = "test-loopback") {
        "SDROP_TEST_ACCESS_TOKEN"
    } else {
        "SDROP_ACCESS_TOKEN"
    };
    env_secret(var)
        .map(|t| checked(Credentials::User(t)))
        .transpose()
}

/// Token after an Access redirect: from cloudflared (in the test build cloudflared is not invoked;
/// SDROP_TEST_CLOUDFLARED_TOKEN emulates its answer).
pub fn user_login(origin: &Origin) -> Result<Credentials, CliError> {
    if cfg!(feature = "test-loopback") {
        let _ = origin;
        return match env_secret("SDROP_TEST_CLOUDFLARED_TOKEN") {
            Some(t) => checked(Credentials::User(t)),
            None => err(
                "Cloudflare Access login is required (test build: set SDROP_TEST_CLOUDFLARED_TOKEN)",
            ),
        };
    }
    checked(Credentials::User(cloudflared_token(origin)?))
}

#[cfg(not(feature = "test-loopback"))]
fn cloudflared_token(origin: &Origin) -> Result<Zeroizing<String>, CliError> {
    use std::process::{Command, Stdio};
    let token = || -> Option<Zeroizing<String>> {
        let out = Command::new("cloudflared")
            .args(["access", "token", &format!("-app={}", origin.as_str())])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        let t = Zeroizing::new(String::from_utf8(out.stdout).ok()?.trim().to_owned());
        (out.status.success() && t.split('.').count() == 3 && header_safe(&t)).then_some(t)
    };
    if let Some(t) = token() {
        return Ok(t);
    }
    eprintln!("Signing in to Cloudflare Access with cloudflared...");
    let login = Command::new("cloudflared")
        .args(["access", "login", origin.as_str()])
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status();
    match login {
        Err(_) => err("cloudflared is not installed: install it or set SDROP_ACCESS_TOKEN"),
        Ok(s) if !s.success() => err("cloudflared access login failed"),
        Ok(_) => token().map_or_else(|| err("cloudflared did not return an Access token"), Ok),
    }
}

#[cfg(feature = "test-loopback")]
fn cloudflared_token(_origin: &Origin) -> Result<Zeroizing<String>, CliError> {
    err("test build never calls cloudflared")
}
