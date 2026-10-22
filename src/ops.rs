//! Service operations without printing or terminal input (FORMAT.md 6): the limit, create,
//! consume, status and revoke. Shared by the CLI commands and the TUI.

use crate::access::{self, Credentials};
use crate::api::{self, CliError, Origin, OwnerLink, RecipientLink, err, http_error};
use crate::format::{self, Content, FormatError};
use serde_json::Value;
use zeroize::Zeroizing;

/// The trusted service with the user's Access credentials. The explicit token is read right before
/// the first request (after all local checks, as the CLI always did); on an Access redirect without
/// a token one is obtained and the request is retried once.
pub struct Client {
    pub origin: Origin,
    agent: ureq::Agent,
    creds: Option<Credentials>,
    creds_read: bool,
    /// May run the interactive `cloudflared access login` (CLI); the TUI must not.
    interactive_login: bool,
}

/// Links of a created secret.
pub struct Created {
    /// `origin/s/<id>#<K_url>[~p]`: for the recipient.
    pub recipient: Zeroizing<String>,
    /// `origin/o/<id>#<ownerToken>`: for the sender only.
    pub owner: Zeroizing<String>,
    /// ISO 8601, printable.
    pub expires: String,
}

/// Status of a secret (strings are printable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub state: String,
    pub created: String,
    pub expires: String,
    pub consumed_at: Option<String>,
    pub consumed_by: Option<String>,
}

/// Result of a revoke request.
pub enum Revoked {
    Done,
    AlreadyRead(Status),
}

pub const NOT_FOUND: &str = "secret not found, already read, revoked or expired. If you didn't open it yourself, tell the sender.";

fn json(body: &[u8]) -> Result<Value, CliError> {
    serde_json::from_slice(body)
        .map_err(|_| CliError::Msg("the server returned an unexpected answer".into()))
}

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str, CliError> {
    v.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Msg("the server returned an unexpected answer".into()))
}

fn status_of(v: &Value) -> Result<Status, CliError> {
    let opt = |name: &str| v.get(name).and_then(Value::as_str).map(api::printable);
    Ok(Status {
        state: api::printable(field(v, "state")?),
        created: api::printable(field(v, "createdAt")?),
        expires: api::printable(field(v, "expiresAt")?),
        consumed_at: opt("consumedAt"),
        consumed_by: opt("consumedBy"),
    })
}

pub fn human_size(n: usize) -> String {
    if n >= 1 << 20 {
        format!("{} MB", n >> 20)
    } else if n >= 1024 {
        format!("{} KB", n >> 10)
    } else {
        format!("{n} B")
    }
}

impl Client {
    /// The configured origin (SDROP_ORIGIN or the built-in one). No credentials are read yet.
    pub fn new(interactive_login: bool) -> Result<Client, CliError> {
        Ok(Client::with_origin(
            Origin::configured()?,
            interactive_login,
        ))
    }

    /// A given trusted origin (tests drive the TUI against a local server with it).
    pub fn with_origin(origin: Origin, interactive_login: bool) -> Client {
        Client {
            origin,
            agent: api::agent(),
            creds: None,
            creds_read: false,
            interactive_login,
        }
    }

    /// Recipient link parsed against the trusted origin, before any request.
    pub fn recipient_link(&self, url: &str) -> Result<RecipientLink, CliError> {
        api::parse_recipient_link(&self.origin, url)
    }

    /// Sender link parsed against the trusted origin, before any request.
    pub fn owner_link(&self, url: &str) -> Result<OwnerLink, CliError> {
        api::parse_owner_link(&self.origin, url)
    }

    fn call(
        &mut self,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<api::Reply, CliError> {
        if !self.creds_read {
            self.creds = access::user_preset()?;
            self.creds_read = true;
        }
        let send = |c: &Client| {
            api::call(
                &c.agent,
                &c.origin,
                method,
                path,
                c.creds.as_ref(),
                extra,
                body,
            )
        };
        match send(self) {
            // The redirect is Access asking for login: the request never reached the service.
            Err(CliError::Redirect(_)) if self.creds.is_none() => {
                self.creds = Some(access::user_login(&self.origin, self.interactive_login)?);
                send(self)
            }
            r => r,
        }
    }

    /// Service limit (`GET /api/limits`): one of the format buckets.
    pub fn limit(&mut self) -> Result<usize, CliError> {
        let r = self.call("GET", "/api/limits", &[], None)?;
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

    /// Encrypt under the service limit and create the secret.
    pub fn create(
        &mut self,
        content: &Content,
        passphrase: Option<&str>,
        ttl: u32,
    ) -> Result<Created, CliError> {
        let limit = self.limit()?;
        let (envelope, k_url) = match format::encrypt(content, passphrase, limit) {
            Err(FormatError::TooLarge) => {
                return err(format!(
                    "the secret is larger than the service limit of {}",
                    human_size(limit)
                ));
            }
            r => r?,
        };
        let r = self.call(
            "POST",
            &format!("/api/secrets?ttl={ttl}"),
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
        Ok(Created {
            recipient: Zeroizing::new(format!(
                "{}/s/{id}#{}{suffix}",
                self.origin.as_str(),
                format::encode_base64url(&*k_url)
            )),
            owner: Zeroizing::new(format!("{}/o/{id}#{token}", self.origin.as_str())),
            expires: api::printable(expires),
        })
    }

    /// Fetch the envelope; the server deletes it at the same moment (FORMAT.md 6).
    pub fn consume(&mut self, link: &RecipientLink) -> Result<Zeroizing<Vec<u8>>, CliError> {
        let path = format!("/api/secrets/{}/consume", link.id);
        let r = self.call("POST", &path, &[], None).map_err(|e| match e {
            // Network dropped: consume may already have happened (FORMAT.md 6: at most one delivery).
            CliError::Network(m) => CliError::Msg(format!(
                "{m}. The result is unknown: the secret may already be destroyed on the server. \
                 Try again; if it is then not found, ask the sender to send it again."
            )),
            other => other,
        })?;
        match r.status {
            200 => Ok(Zeroizing::new(r.body)),
            404 => err(NOT_FOUND),
            s => Err(http_error("fetching the secret failed", s)),
        }
    }

    pub fn status(&mut self, link: &OwnerLink) -> Result<Status, CliError> {
        let auth = Zeroizing::new(format!("Bearer {}", link.token.as_str()));
        let r = self.call(
            "GET",
            &format!("/api/secrets/{}/status", link.id),
            &[("Authorization", &auth)],
            None,
        )?;
        match r.status {
            200 => status_of(&json(&r.body)?),
            404 => err("secret not found or expired"),
            s => Err(http_error("fetching the status failed", s)),
        }
    }

    pub fn revoke(&mut self, link: &OwnerLink) -> Result<Revoked, CliError> {
        let auth = Zeroizing::new(format!("Bearer {}", link.token.as_str()));
        let r = self.call(
            "DELETE",
            &format!("/api/secrets/{}", link.id),
            &[("Authorization", &auth)],
            None,
        )?;
        match r.status {
            204 => Ok(Revoked::Done),
            409 => Ok(Revoked::AlreadyRead(status_of(&json(&r.body)?)?)),
            404 => err("secret not found or expired"),
            s => Err(http_error("revoking failed", s)),
        }
    }
}
