//! T20: command behavior against a local HTTP server with a request counter (build with
//! `--features test-loopback`). Link and input are checked before the network; test tokens only.
#![cfg(feature = "test-loopback")]
// Unix file modes and shell tricks (ulimit, read-only directories) are checked on Unix only;
// helpers used only there are unused on Windows.
#![cfg_attr(not(unix), allow(dead_code))]

use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
struct Req {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

type Handler = dyn Fn(&Req) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + Sync;

struct Fake {
    origin: String,
    log: Arc<Mutex<Vec<Req>>>,
}

impl Fake {
    fn start(handler: Box<Handler>) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let (log2, handler) = (log.clone(), Arc::new(handler));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line.is_empty() {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let (method, path) = (
                    parts.next().unwrap_or("").to_owned(),
                    parts.next().unwrap_or("").to_owned(),
                );
                let mut headers = Vec::new();
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    let h = h.trim_end();
                    if h.is_empty() {
                        break;
                    }
                    let (k, v) = h.split_once(':').unwrap();
                    headers.push((k.trim().to_ascii_lowercase(), v.trim().to_owned()));
                }
                let len = headers
                    .iter()
                    .find(|(k, _)| k == "content-length")
                    .map_or(0, |(_, v)| v.parse().unwrap());
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                let req = Req {
                    method,
                    path,
                    headers,
                    body,
                };
                log2.lock().unwrap().push(req.clone());
                let (status, extra, body) = handler(&req);
                let mut head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (k, v) in extra {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        Fake { origin, log }
    }

    fn requests(&self) -> Vec<Req> {
        self.log.lock().unwrap().clone()
    }
}

fn spec(name: &str) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(format!("{}/spec/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap(),
    )
    .unwrap()
}

fn vector(name: &str) -> Value {
    spec("vectors.json")
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()
        .clone()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Directory with a fake cloudflared that leaves a marker when run.
fn fake_cloudflared() -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "sdrop-test-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let marker = dir.join("cloudflared-was-called");
    let script = dir.join("cloudflared");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\necho a.b.c\n", marker.display()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    (dir, marker)
}

/// PATH with `dir` first (where the fake cloudflared lives), in the platform's syntax.
fn path_with(dir: &std::path::Path) -> std::ffi::OsString {
    let rest = std::env::var_os("PATH").unwrap_or_default();
    std::env::join_paths(std::iter::once(dir.to_path_buf()).chain(std::env::split_paths(&rest)))
        .unwrap()
}

/// Variables a process needs to run at all after `env_clear` (Windows: networking needs
/// SystemRoot); nothing with credentials.
fn platform_env() -> Vec<(String, String)> {
    if cfg!(windows) {
        std::env::vars()
            .filter(|(k, _)| k.eq_ignore_ascii_case("SYSTEMROOT"))
            .collect()
    } else {
        Vec::new()
    }
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

const TEST_TOKEN: &str = "test-user:alice@example.com";
const REAL: &str = "REAL-SECRET-CREDENTIAL";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    cloudflared_called: bool,
    /// Working directory of the run (a fresh temporary one).
    cwd: PathBuf,
}

fn sdrop(origin: &str, args: &[&str], stdin: &[u8]) -> Run {
    sdrop_tty(origin, args, stdin, None)
}

/// `tty`: lines the "terminal" returns to passphrase prompts (one per prompt).
fn sdrop_tty(origin: &str, args: &[&str], stdin: &[u8], tty: Option<&[&str]>) -> Run {
    let (dir, marker) = fake_cloudflared();
    let tty_file = dir.join("tty");
    if let Some(lines) = tty {
        std::fs::write(&tty_file, lines.join("\n") + "\n").unwrap();
    }
    let path = path_with(&dir);
    let cwd = dir.join("cwd");
    std::fs::create_dir_all(&cwd).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_sdrop"))
        .args(args)
        .current_dir(&cwd)
        .env_clear()
        .envs(platform_env())
        .env("PATH", path)
        .env("SDROP_ORIGIN", origin)
        .env("SDROP_TEST_ACCESS_TOKEN", TEST_TOKEN)
        .env("SDROP_ACCESS_TOKEN", REAL)
        .env("SDROP_TEST_TTY_INPUT", &tty_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // sdrop may exit before reading stdin (bad arguments): a closed pipe is not a test failure.
    match child.stdin.take().unwrap().write_all(stdin) {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => panic!("stdin: {e}"),
        _ => {}
    }
    let out = child.wait_with_output().unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        cloudflared_called: marker.exists(),
        cwd,
    }
}

fn never_called() -> Fake {
    Fake::start(Box::new(|_| (500, vec![], b"must not be called".to_vec())))
}

const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn broken_links_make_no_requests() {
    let f = never_called();
    let key = vector("plain-ascii")["k_url"].as_str().unwrap().to_owned();
    let mut urls = vec![
        format!("https://evil.example/s/{ID}#{key}"),
        format!("{}.evil/s/{ID}#{key}", f.origin),
        format!("{}/s/{ID}", f.origin),
        format!("{}/s/{}#{key}", f.origin, &ID[1..]),
        format!("{}/s/{}#{key}", f.origin, ID.to_uppercase()),
        format!("{}/o/{ID}#{key}", f.origin),
        format!("{}/s/{ID}/#{key}", f.origin),
    ];
    for l in spec("links.json")["invalid"].as_array().unwrap() {
        urls.push(format!(
            "{}/s/{ID}#{}",
            f.origin,
            l["fragment"].as_str().unwrap()
        ));
    }
    for url in &urls {
        let r = sdrop(&f.origin, &["get", url], b"");
        assert_ne!(r.code, 0, "{url}");
        assert!(!r.cloudflared_called);
    }
    for cmd in ["status", "revoke"] {
        for url in [
            format!("{}/o/{ID}#short", f.origin),
            format!("{}/o/{ID}#{}B", f.origin, "A".repeat(42)),
            format!("{}/s/{ID}#{key}", f.origin),
        ] {
            assert_ne!(sdrop(&f.origin, &[cmd, &url], b"").code, 0, "{cmd} {url}");
        }
    }
    assert_eq!(f.requests().len(), 0);
}

#[test]
fn bad_input_makes_no_requests() {
    let f = never_called();
    for (stdin, args) in [
        (vec![0xff, 0xfe, b'a'], vec!["put"]),
        (vec![], vec!["put"]),
        (vec![b'a'; 1_100_000], vec!["put"]),
        (b"x".to_vec(), vec!["put", "--ttl", "2h"]),
        (b"x".to_vec(), vec!["put", "/nonexistent/secret.txt"]),
        (b"x".to_vec(), vec!["put", "--passphrase-file", "/dev/null"]),
    ] {
        let r = sdrop(&f.origin, &args, &stdin);
        assert_ne!(r.code, 0, "{args:?}");
    }
    assert_eq!(f.requests().len(), 0);
}

#[test]
fn foreign_origin_config_rejected() {
    let f = never_called();
    for origin in [
        "http://localhost:1",
        "http://10.0.0.1:80",
        "ftp://127.0.0.1:1",
        "http://127.0.0.1",
        "https://Example.com",
        "https://a.com/path",
    ] {
        let r = sdrop(origin, &["put"], b"x");
        assert_ne!(r.code, 0, "{origin}");
        assert!(
            r.stderr.contains("not an allowed origin"),
            "{origin}: {}",
            r.stderr
        );
    }
    assert_eq!(f.requests().len(), 0);
}

fn created(origin: String) -> impl Fn(&Req) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let _ = origin;
    |q: &Req| {
        if q.path == "/api/limits" {
            return (200, vec![], br#"{"maxBucket":262144}"#.to_vec());
        }
        let body = serde_json::json!({ "id": ID, "expiresAt": "2026-10-22T00:00:00.000Z", "ownerToken": "A".repeat(43) });
        (
            201,
            vec![("Content-Type".into(), "application/json".into())],
            body.to_string().into_bytes(),
        )
    }
}

#[test]
fn put_sends_only_test_credentials_and_prints_links_apart() {
    let f = Fake::start(Box::new(created(String::new())));
    let r = sdrop(&f.origin, &["put", "--ttl", "1h"], "секрет\n".as_bytes());
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(!r.cloudflared_called);
    let reqs = f.requests();
    assert_eq!(reqs.len(), 2);
    assert_eq!(
        (reqs[0].method.as_str(), reqs[0].path.as_str()),
        ("GET", "/api/limits")
    );
    let q = &reqs[1];
    assert_eq!(
        (q.method.as_str(), q.path.as_str()),
        ("POST", "/api/secrets?ttl=3600")
    );
    let h = |k: &str| {
        q.headers
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(h("cf-access-token").as_deref(), Some(TEST_TOKEN));
    assert_eq!(h("x-secret-drop").as_deref(), Some("1"));
    assert_eq!(
        h("content-type").as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(h("cf-access-client-id"), None);
    assert!(!format!("{:?}", q.headers).contains(REAL));
    assert_eq!(q.body.len(), 1074);
    assert_eq!(&q.body[..6], b"SDRP\x01\x00");
    // stdout holds only the recipient link; the sender link goes to stderr.
    let link = r.stdout.trim_end();
    assert_eq!(r.stdout.lines().count(), 1);
    assert!(link.starts_with(&format!("{}/s/{ID}#", f.origin)), "{link}");
    let frag = link.split('#').nth(1).unwrap();
    assert_eq!(frag.len(), 43);
    assert!(
        r.stderr
            .contains(&format!("{}/o/{ID}#{}", f.origin, "A".repeat(43)))
    );
    assert!(!r.stderr.contains(frag));
}

#[test]
fn put_with_passphrase_file_adds_suffix_and_flag() {
    let f = Fake::start(Box::new(created(String::new())));
    let dir = std::env::temp_dir().join(format!("sdrop-pass-{}", rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    let pf = dir.join("pass");
    std::fs::write(&pf, "horse\n").unwrap();
    let r = sdrop(
        &f.origin,
        &["put", "--passphrase-file", pf.to_str().unwrap()],
        b"x",
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.trim_end().ends_with("~p"));
    assert_eq!(f.requests()[1].body[5], 1);
}

fn serving(envelope: Vec<u8>) -> Fake {
    Fake::start(Box::new(move |q| {
        if q.method == "POST" && q.path.ends_with("/consume") {
            (
                200,
                vec![("Content-Type".into(), "application/octet-stream".into())],
                envelope.clone(),
            )
        } else {
            (404, vec![], br#"{"error":"not_found"}"#.to_vec())
        }
    }))
}

#[test]
fn get_prints_exact_text_once() {
    let v = vector("escapes");
    let f = serving(hex(v["envelope_hex"].as_str().unwrap()));
    let url = format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap());
    let r = sdrop(&f.origin, &["get", &url], b"");
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, v["text"].as_str().unwrap());
    assert_eq!(f.requests().len(), 1);
    assert_eq!(f.requests()[0].path, format!("/api/secrets/{ID}/consume"));
    assert!(!r.stderr.contains(v["k_url"].as_str().unwrap()));
}

#[test]
fn get_url_from_stdin() {
    let v = vector("plain-ascii");
    let f = serving(hex(v["envelope_hex"].as_str().unwrap()));
    let url = format!("{}/s/{ID}#{}\n", f.origin, v["k_url"].as_str().unwrap());
    let r = sdrop(&f.origin, &["get", "-"], url.as_bytes());
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, v["text"].as_str().unwrap());
}

#[test]
fn get_passphrase_by_hint_and_by_flag() {
    let v = vector("passphrase-ascii");
    let dir = std::env::temp_dir().join(format!("sdrop-pass-{}", rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    let pf = dir.join("pass");
    std::fs::write(&pf, format!("{}\r\n", v["passphrase"].as_str().unwrap())).unwrap();
    for suffix in ["~p", ""] {
        let f = serving(hex(v["envelope_hex"].as_str().unwrap()));
        let url = format!(
            "{}/s/{ID}#{}{suffix}",
            f.origin,
            v["k_url"].as_str().unwrap()
        );
        let r = sdrop(
            &f.origin,
            &["get", &url, "--passphrase-file", pf.to_str().unwrap()],
            b"",
        );
        assert_eq!(r.code, 0, "{suffix}: {}", r.stderr);
        assert_eq!(r.stdout, v["text"].as_str().unwrap());
        assert_eq!(f.requests().len(), 1);
    }
}

#[test]
fn get_wrong_passphrase_from_file_fails_after_one_consume() {
    let v = vector("passphrase-ascii");
    let dir = std::env::temp_dir().join(format!("sdrop-pass-{}", rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    let pf = dir.join("pass");
    std::fs::write(&pf, "wrong\n").unwrap();
    let f = serving(hex(v["envelope_hex"].as_str().unwrap()));
    let url = format!("{}/s/{ID}#{}~p", f.origin, v["k_url"].as_str().unwrap());
    let r = sdrop(
        &f.origin,
        &["get", &url, "--passphrase-file", pf.to_str().unwrap()],
        b"",
    );
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("wrong passphrase"));
    assert_eq!(f.requests().len(), 1);
}

#[test]
fn not_found_and_damaged() {
    let v = vector("plain-ascii");
    let f = never_called();
    let gone = Fake::start(Box::new(|_| {
        (404, vec![], br#"{"error":"not_found"}"#.to_vec())
    }));
    let r = sdrop(
        &gone.origin,
        &[
            "get",
            &format!("{}/s/{ID}#{}", gone.origin, v["k_url"].as_str().unwrap()),
        ],
        b"",
    );
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("already read"));
    let bad = vector("plain-ascii");
    let mut env = hex(bad["envelope_hex"].as_str().unwrap());
    env[40] ^= 1;
    let d = serving(env);
    let r = sdrop(
        &d.origin,
        &[
            "get",
            &format!("{}/s/{ID}#{}", d.origin, v["k_url"].as_str().unwrap()),
        ],
        b"",
    );
    assert_ne!(r.code, 0);
    assert_eq!(r.stdout, "");
    assert_eq!(f.requests().len(), 0);
}

#[test]
fn redirect_is_not_followed() {
    let target = never_called();
    let to = format!("{}/login", target.origin);
    let f = Fake::start(Box::new(move |_| {
        (302, vec![("Location".into(), to.clone())], vec![])
    }));
    let v = vector("plain-ascii");
    let r = sdrop(
        &f.origin,
        &[
            "get",
            &format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap()),
        ],
        b"",
    );
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("redirect"), "{}", r.stderr);
    assert_eq!(f.requests().len(), 1);
    assert_eq!(target.requests().len(), 0);
}

#[test]
fn oversized_response_rejected() {
    let f = Fake::start(Box::new(|_| (200, vec![], vec![0u8; 2 << 20])));
    let v = vector("plain-ascii");
    let r = sdrop(
        &f.origin,
        &[
            "get",
            &format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap()),
        ],
        b"",
    );
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("too large"), "{}", r.stderr);
}

#[test]
fn status_and_revoke_send_bearer_and_print() {
    let token = "B".repeat(42) + "A";
    let f = Fake::start(Box::new(|q| {
        match q.method.as_str() {
        "GET" => (200, vec![], br#"{"state":"consumed","createdAt":"c","expiresAt":"e","consumedAt":"t","consumedBy":"bob@x"}"#.to_vec()),
        _ => (409, vec![], br#"{"state":"consumed","createdAt":"c","expiresAt":"e","consumedAt":"t","consumedBy":"bob@x"}"#.to_vec()),
    }
    }));
    let url = format!("{}/o/{ID}#{token}", f.origin);
    let r = sdrop(&f.origin, &["status", &url], b"");
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("read:    t by bob@x"));
    let r = sdrop(&f.origin, &["revoke", &url], b"");
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("already read"));
    let reqs = f.requests();
    assert_eq!(reqs.len(), 2);
    for q in &reqs {
        assert!(
            q.headers
                .contains(&("authorization".into(), format!("Bearer {token}")))
        );
    }
    assert_eq!(
        (reqs[1].method.as_str(), reqs[1].path.clone()),
        ("DELETE", format!("/api/secrets/{ID}"))
    );
}

#[test]
fn secret_is_never_an_argument() {
    let f = never_called();
    let r = sdrop(&f.origin, &["put", "--secret", "x"], b"");
    assert_eq!(r.code, 2);
    let r = sdrop(&f.origin, &["put", "--passphrase", "hunter2"], b"x");
    assert_ne!(r.code, 0);
    assert_eq!(f.requests().len(), 0);
}

fn temp_file(content: &[u8]) -> String {
    let dir = std::env::temp_dir().join(format!("sdrop-f-{}", rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("f");
    std::fs::write(&f, content).unwrap();
    f.to_str().unwrap().to_owned()
}

#[test]
fn link_from_pipe_passphrase_from_tty_retries_after_typo() {
    let v = vector("passphrase-ascii");
    let pass = v["passphrase"].as_str().unwrap();
    for suffix in ["~p", ""] {
        let f = serving(hex(v["envelope_hex"].as_str().unwrap()));
        let url = format!(
            "{}/s/{ID}#{}{suffix}\n",
            f.origin,
            v["k_url"].as_str().unwrap()
        );
        let r = sdrop_tty(
            &f.origin,
            &["get", "-"],
            url.as_bytes(),
            Some(&["typo", pass]),
        );
        assert_eq!(r.code, 0, "{suffix}: {}", r.stderr);
        assert_eq!(r.stdout, v["text"].as_str().unwrap());
        assert_eq!(f.requests().len(), 1, "{suffix}");
        assert!(r.stderr.contains("Wrong passphrase"));
    }
}

#[test]
fn tty_three_wrong_attempts_then_error_one_consume() {
    let v = vector("passphrase-ascii");
    let f = serving(hex(v["envelope_hex"].as_str().unwrap()));
    let url = format!("{}/s/{ID}#{}~p", f.origin, v["k_url"].as_str().unwrap());
    let r = sdrop_tty(&f.origin, &["get", &url], b"", Some(&["a", "b", "c", "d"]));
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("wrong passphrase"));
    assert_eq!(r.stderr.matches("Passphrase: ").count(), 3);
    assert_eq!(f.requests().len(), 1);
}

#[test]
fn bad_passphrase_file_is_rejected_before_any_request() {
    let v = vector("passphrase-ascii");
    let f = never_called();
    let missing = "/nonexistent/pass".to_owned();
    let empty = temp_file(b"");
    let blank = temp_file(b"\n");
    let binary = temp_file(&[0xff, 0xfe]);
    for suffix in ["", "~p"] {
        for pf in [&missing, &empty, &blank, &binary] {
            let url = format!(
                "{}/s/{ID}#{}{suffix}",
                f.origin,
                v["k_url"].as_str().unwrap()
            );
            let r = sdrop(&f.origin, &["get", &url, "--passphrase-file", pf], b"");
            assert_ne!(r.code, 0, "{suffix} {pf}");
        }
    }
    assert_eq!(f.requests().len(), 0);
}

#[test]
fn passphrase_file_given_without_hint_is_used_after_fetch() {
    let v = vector("passphrase-ascii");
    let f = serving(hex(v["envelope_hex"].as_str().unwrap()));
    let pf = temp_file(v["passphrase"].as_str().unwrap().as_bytes());
    let url = format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap());
    let r = sdrop_tty(
        &f.origin,
        &["get", &url, "--passphrase-file", &pf],
        b"",
        Some(&[]),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, v["text"].as_str().unwrap());
    assert!(!r.stderr.contains("Passphrase: "));
}

#[test]
fn put_passphrase_from_tty_must_be_repeated() {
    let f = Fake::start(Box::new(created(String::new())));
    let r = sdrop_tty(
        &f.origin,
        &["put", "--passphrase"],
        b"x",
        Some(&["one", "two"]),
    );
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("do not match"));
    assert_eq!(f.requests().len(), 0);
    let r = sdrop_tty(
        &f.origin,
        &["put", "--passphrase"],
        b"x",
        Some(&["same", "same"]),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.trim_end().ends_with("~p"));
}

#[test]
fn empty_input_after_burn_is_asked_again() {
    let v = vector("passphrase-ascii");
    let pass = v["passphrase"].as_str().unwrap();
    for (suffix, tty) in [
        ("~p", vec!["typo", "", pass]),
        ("", vec!["", pass]),
        ("", vec!["", "", "typo", "", pass]),
    ] {
        let f = serving(hex(v["envelope_hex"].as_str().unwrap()));
        let url = format!(
            "{}/s/{ID}#{}{suffix}",
            f.origin,
            v["k_url"].as_str().unwrap()
        );
        let r = sdrop_tty(&f.origin, &["get", &url], b"", Some(&tty));
        assert_eq!(r.code, 0, "{suffix} {tty:?}: {}", r.stderr);
        assert_eq!(r.stdout, v["text"].as_str().unwrap());
        assert_eq!(f.requests().len(), 1);
    }
}

#[test]
fn empty_passphrase_before_request_makes_no_request() {
    let v = vector("passphrase-ascii");
    let f = never_called();
    let url = format!("{}/s/{ID}#{}~p", f.origin, v["k_url"].as_str().unwrap());
    let r = sdrop_tty(&f.origin, &["get", &url], b"", Some(&[""]));
    assert_ne!(r.code, 0);
    assert_eq!(f.requests().len(), 0);
}

/// Run without SDROP_TEST_ACCESS_TOKEN (public mode or login via redirect); `login` is what
/// "cloudflared returns" (SDROP_TEST_CLOUDFLARED_TOKEN).
fn sdrop_public(origin: &str, args: &[&str], stdin: &[u8], login: Option<&str>) -> Run {
    let (dir, marker) = fake_cloudflared();
    let path = path_with(&dir);
    let mut c = Command::new(env!("CARGO_BIN_EXE_sdrop"));
    c.args(args)
        .env_clear()
        .envs(platform_env())
        .env("PATH", path)
        .env("SDROP_ORIGIN", origin)
        .env("SDROP_ACCESS_TOKEN", REAL)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(t) = login {
        c.env("SDROP_TEST_CLOUDFLARED_TOKEN", t);
    }
    let mut child = c.spawn().unwrap();
    // sdrop may exit before reading stdin (bad arguments): a closed pipe is not a test failure.
    match child.stdin.take().unwrap().write_all(stdin) {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => panic!("stdin: {e}"),
        _ => {}
    }
    let out = child.wait_with_output().unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        cloudflared_called: marker.exists(),
        cwd: dir,
    }
}

fn has_token(q: &Req) -> bool {
    q.headers.iter().any(|(k, _)| k == "cf-access-token")
}

#[test]
fn public_mode_works_without_any_token() {
    let f = Fake::start(Box::new(created(String::new())));
    let r = sdrop_public(&f.origin, &["put"], b"x", None);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(!r.cloudflared_called);
    let reqs = f.requests();
    assert_eq!(reqs.len(), 2);
    for q in &reqs {
        assert!(!has_token(q));
        assert!(!format!("{:?}", q.headers).contains(REAL));
    }
}

/// Like Access: without cf-access-token, 302 to login; with a token, the service's response.
fn behind_access(envelope: Vec<u8>) -> Fake {
    Fake::start(Box::new(move |q| {
        if !q.headers.iter().any(|(k, _)| k == "cf-access-token") {
            return (
                302,
                vec![(
                    "Location".into(),
                    "https://team.cloudflareaccess.com/login".into(),
                )],
                vec![],
            );
        }
        if q.path == "/api/limits" {
            (200, vec![], br#"{"maxBucket":262144}"#.to_vec())
        } else if q.path.ends_with("/consume") {
            (200, vec![], envelope.clone())
        } else {
            let body = serde_json::json!({ "id": ID, "expiresAt": "2026-10-22T00:00:00.000Z", "ownerToken": "A".repeat(43) });
            (201, vec![], body.to_string().into_bytes())
        }
    }))
}

#[test]
fn access_redirect_gets_token_and_retries_once() {
    let v = vector("plain-ascii");
    let f = behind_access(hex(v["envelope_hex"].as_str().unwrap()));
    let url = format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap());
    let r = sdrop_public(
        &f.origin,
        &["get", &url],
        b"",
        Some("test-user:late@example.com"),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, v["text"].as_str().unwrap());
    let reqs = f.requests();
    assert_eq!(reqs.len(), 2);
    assert!(!has_token(&reqs[0]));
    assert!(reqs[1].headers.contains(&(
        "cf-access-token".into(),
        "test-user:late@example.com".into()
    )));
    let r = sdrop_public(
        &f.origin,
        &["put"],
        b"x",
        Some("test-user:late@example.com"),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
}

#[test]
fn second_redirect_is_an_error() {
    let f = Fake::start(Box::new(|_| {
        (
            302,
            vec![("Location".into(), "https://login.example/".into())],
            vec![],
        )
    }));
    let v = vector("plain-ascii");
    let url = format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap());
    let r = sdrop_public(
        &f.origin,
        &["get", &url],
        b"",
        Some("test-user:a@example.com"),
    );
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("redirect"));
    assert_eq!(f.requests().len(), 2);
    let r = sdrop_public(&f.origin, &["get", &url], b"", None);
    assert_ne!(r.code, 0);
    assert_eq!(f.requests().len(), 3);
}

// ---------- Files (FORMAT.md 3, README) ----------

/// Server that returns the envelope on consume and the `limit` on /api/limits.
fn serving_with_limit(envelope: Vec<u8>, limit: usize) -> Fake {
    Fake::start(Box::new(move |q| {
        match (q.method.as_str(), q.path.as_str()) {
            ("GET", "/api/limits") => (
                200,
                vec![],
                format!("{{\"maxBucket\":{limit}}}").into_bytes(),
            ),
            ("POST", p) if p.ends_with("/consume") => (200, vec![], envelope.clone()),
            ("POST", p) if p.starts_with("/api/secrets?") => {
                let body = serde_json::json!({ "id": ID, "expiresAt": "2026-10-22T00:00:00.000Z", "ownerToken": "A".repeat(43) });
                (201, vec![], body.to_string().into_bytes())
            }
            _ => (404, vec![], br#"{"error":"not_found"}"#.to_vec()),
        }
    }))
}

fn file_vector() -> (String, Vec<u8>, String, Vec<u8>) {
    let v = vector("file-cyrillic-name");
    let f = &v["file"];
    (
        v["k_url"].as_str().unwrap().to_owned(),
        hex(v["envelope_hex"].as_str().unwrap()),
        f["name"].as_str().unwrap().to_owned(),
        hex(f["data_hex"].as_str().unwrap()),
    )
}

#[cfg(unix)]
fn mode(p: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn put_file_sends_name_and_bytes_after_limit() {
    let f = serving_with_limit(vec![], 262144);
    let src = temp_file(&[0, 1, 2, 255, 0]);
    let r = sdrop(&f.origin, &["put", "--file", &src], b"");
    assert_eq!(r.code, 0, "{}", r.stderr);
    let reqs = f.requests();
    assert_eq!(
        reqs.iter().map(|q| q.path.as_str()).collect::<Vec<_>>(),
        ["/api/limits", "/api/secrets?ttl=86400"]
    );
    let link = r.stdout.trim_end();
    let key = sdrop::format::decode_key(link.split('#').nth(1).unwrap()).unwrap();
    match sdrop::format::decrypt(&reqs[1].body, &key, None).unwrap() {
        sdrop::format::Secret::File { name, data } => {
            assert_eq!(name, "f");
            assert_eq!(data.as_slice(), &[0, 1, 2, 255, 0]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn put_over_service_limit_fails_before_upload() {
    let f = serving_with_limit(vec![], 65536);
    let src = temp_file(&vec![7u8; 100_000]);
    let r = sdrop(&f.origin, &["put", "--file", &src], b"");
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("limit of 64 KB"), "{}", r.stderr);
    assert_eq!(
        f.requests()
            .iter()
            .map(|q| q.path.as_str())
            .collect::<Vec<_>>(),
        ["/api/limits"]
    );
}

#[test]
fn put_binary_text_suggests_file() {
    let f = never_called();
    let r = sdrop(&f.origin, &["put"], &[0xff, 0xfe]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("not UTF-8"), "{}", r.stderr);
    assert_eq!(f.requests().len(), 0);
}

#[test]
#[cfg(unix)]
fn get_file_without_output_goes_to_private_dir_not_sender_name() {
    let (k, env, name, data) = file_vector();
    let f = serving_with_limit(env, 262144);
    let url = format!("{}/s/{ID}#{k}", f.origin);
    let pass = temp_file("пароль".as_bytes());
    let r = sdrop(&f.origin, &["get", &url, "--passphrase-file", &pass], b"");
    assert_eq!(r.code, 0, "{}", r.stderr);
    let dir = r.cwd.join(format!("sdrop-{}", &ID[..8]));
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("data")), 0o600);
    assert_eq!(std::fs::read(dir.join("data")).unwrap(), data);
    let entries: Vec<_> = std::fs::read_dir(&r.cwd)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        entries,
        [std::ffi::OsString::from(format!("sdrop-{}", &ID[..8]))]
    );
    assert!(r.stderr.contains(&name), "{}", r.stderr);
    assert_eq!(r.stdout, "");
}

#[test]
#[cfg(unix)]
fn get_file_dotfile_name_never_used_as_path() {
    let v = vector("file-small");
    let k = sdrop::format::decode_key(v["k_url"].as_str().unwrap()).unwrap();
    let env = sdrop::format::encrypt_with(
        &sdrop::format::Content::File {
            name: ".zshenv",
            data: b"echo pwned",
        },
        &k,
        &[1; 16],
        &[2; 12],
        None,
        262144,
    )
    .unwrap();
    let f = serving_with_limit(env, 262144);
    let r = sdrop(
        &f.origin,
        &[
            "get",
            &format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap()),
        ],
        b"",
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(!r.cwd.join(".zshenv").exists());
    assert_eq!(
        std::fs::read(r.cwd.join(format!("sdrop-{}/data", &ID[..8]))).unwrap(),
        b"echo pwned"
    );
}

#[test]
#[cfg(unix)]
fn get_output_path_checked_before_consume() {
    let (k, env, _, _) = file_vector();
    let f = serving_with_limit(env, 262144);
    let url = format!("{}/s/{ID}#{k}", f.origin);
    let existing = temp_file(b"keep");
    for out in [existing.as_str(), "/nonexistent-dir/x"] {
        let r = sdrop(&f.origin, &["get", &url, "-o", out], b"");
        assert_ne!(r.code, 0, "{out}");
    }
    assert_eq!(std::fs::read(&existing).unwrap(), b"keep");
    assert_eq!(f.requests().len(), 0);
}

#[test]
#[cfg(unix)]
fn get_output_path_and_stdout() {
    let (k, env, _, data) = file_vector();
    let pass = temp_file("пароль".as_bytes());
    let f = serving_with_limit(env.clone(), 262144);
    let dir = std::env::temp_dir().join(format!("sdrop-out-{}", rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("key.pem");
    let url = format!("{}/s/{ID}#{k}", f.origin);
    let r = sdrop(
        &f.origin,
        &[
            "get",
            &url,
            "--passphrase-file",
            &pass,
            "-o",
            out.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(std::fs::read(&out).unwrap(), data);
    assert_eq!(mode(&out), 0o600);
    let f2 = serving_with_limit(env, 262144);
    let url2 = format!("{}/s/{ID}#{k}", f2.origin);
    let out2 = Command::new(env!("CARGO_BIN_EXE_sdrop"))
        .args(["get", &url2, "--passphrase-file", &pass, "-o", "-"])
        .env_clear()
        .envs(platform_env())
        .env("SDROP_ORIGIN", &f2.origin)
        .env("SDROP_TEST_ACCESS_TOKEN", TEST_TOKEN)
        .output()
        .unwrap();
    assert!(out2.status.success());
    assert_eq!(out2.stdout, data);
}

#[test]
#[cfg(unix)]
fn write_failure_after_consume_keeps_secret_and_asks_again() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe_is_root() {
        return;
    }
    let (k, env, _, data) = file_vector();
    let pass = temp_file("пароль".as_bytes());
    let ro = std::env::temp_dir().join(format!("sdrop-ro-{}", rand_suffix()));
    std::fs::create_dir_all(&ro).unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
    let ok = std::env::temp_dir().join(format!("sdrop-ok-{}", rand_suffix()));
    std::fs::create_dir_all(&ok).unwrap();
    let target = ok.join("saved.bin");
    // With a terminal: writing to a read-only directory fails -> another path -> the same bytes.
    let f = serving_with_limit(env.clone(), 262144);
    let url = format!("{}/s/{ID}#{k}", f.origin);
    let r = sdrop_tty(
        &f.origin,
        &[
            "get",
            &url,
            "--passphrase-file",
            &pass,
            "-o",
            ro.join("x").to_str().unwrap(),
        ],
        b"",
        Some(&["", target.to_str().unwrap()]),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stderr.contains("kept in memory"), "{}", r.stderr);
    assert_eq!(std::fs::read(&target).unwrap(), data);
    assert_eq!(f.requests().len(), 1);
    // Without a terminal: the same failure -> the default private directory.
    let f2 = serving_with_limit(env, 262144);
    let url2 = format!("{}/s/{ID}#{k}", f2.origin);
    let r = sdrop(
        &f2.origin,
        &[
            "get",
            &url2,
            "--passphrase-file",
            &pass,
            "-o",
            ro.join("y").to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        std::fs::read(r.cwd.join(format!("sdrop-{}/data", &ID[..8]))).unwrap(),
        data
    );
    assert_eq!(f2.requests().len(), 1);
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn unsafe_is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

#[test]
#[cfg(unix)]
fn existing_file_named_at_prompt_is_never_overwritten() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe_is_root() {
        return;
    }
    let (k, env, _, data) = file_vector();
    let pass = temp_file("пароль".as_bytes());
    let ro = std::env::temp_dir().join(format!("sdrop-ro2-{}", rand_suffix()));
    std::fs::create_dir_all(&ro).unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
    let existing = temp_file(b"precious");
    let fresh = std::env::temp_dir().join(format!("sdrop-fresh-{}", rand_suffix()));
    let f = serving_with_limit(env, 262144);
    let url = format!("{}/s/{ID}#{k}", f.origin);
    let r = sdrop_tty(
        &f.origin,
        &[
            "get",
            &url,
            "--passphrase-file",
            &pass,
            "-o",
            ro.join("x").to_str().unwrap(),
        ],
        b"",
        Some(&[existing.as_str(), fresh.to_str().unwrap()]),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(std::fs::read(&existing).unwrap(), b"precious");
    assert_eq!(std::fs::read(&fresh).unwrap(), data);
    assert_eq!(f.requests().len(), 1);
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// Run with stdout closed immediately: any write to it is an error (EPIPE).
fn sdrop_closed_stdout(origin: &str, args: &[&str], tty: &[&str]) -> (i32, String, PathBuf) {
    sdrop_closed_outputs(origin, args, tty, false)
}

/// stdout (and with `close_stderr`, stderr) closed immediately: any write to them is an error.
fn sdrop_closed_outputs(
    origin: &str,
    args: &[&str],
    tty: &[&str],
    close_stderr: bool,
) -> (i32, String, PathBuf) {
    let (dir, _) = fake_cloudflared();
    let tty_file = dir.join("tty");
    std::fs::write(&tty_file, tty.join("\n") + "\n").unwrap();
    let cwd = dir.join("cwd");
    std::fs::create_dir_all(&cwd).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sdrop"));
    cmd.args(args)
        .current_dir(&cwd)
        .env_clear()
        .envs(platform_env())
        .env("SDROP_ORIGIN", origin)
        .env("SDROP_TEST_ACCESS_TOKEN", TEST_TOKEN)
        .env("SDROP_TEST_TTY_INPUT", &tty_file)
        .stdin(Stdio::null());
    // The read ends are closed before the start: every write fails (EPIPE), with no race
    // against a child that writes before the parent gets to close them.
    let closed = || -> Stdio {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        writer.into()
    };
    cmd.stdout(closed());
    cmd.stderr(if close_stderr {
        closed()
    } else {
        Stdio::piped()
    });
    let out = cmd.spawn().unwrap().wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        cwd,
    )
}

#[test]
fn stdout_failure_after_consume_keeps_secret() {
    // Text to stdout (default) and a file to `-o -`: stdout is closed -> another path from the tty.
    let v = vector("plain-ascii");
    let f = serving_with_limit(hex(v["envelope_hex"].as_str().unwrap()), 262144);
    let target = std::env::temp_dir().join(format!("sdrop-stdout-{}", rand_suffix()));
    let url = format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap());
    let (code, err, _) =
        sdrop_closed_stdout(&f.origin, &["get", &url], &[target.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("kept in memory"), "{err}");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        v["text"].as_str().unwrap()
    );
    assert_eq!(f.requests().len(), 1);
    // Without a terminal: to the default private directory.
    let (k, env, _, data) = file_vector();
    let pass = temp_file("пароль".as_bytes());
    let f2 = serving_with_limit(env, 262144);
    let url2 = format!("{}/s/{ID}#{k}", f2.origin);
    let (code, err, cwd) = sdrop_closed_stdout(
        &f2.origin,
        &["get", &url2, "--passphrase-file", &pass, "-o", "-"],
        &[],
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        std::fs::read(cwd.join(format!("sdrop-{}/data", &ID[..8]))).unwrap(),
        data
    );
    assert_eq!(f2.requests().len(), 1);
}

/// Server that cuts the response off in the middle of the body.
fn truncating_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1074\r\nConnection: close\r\n\r\nSDRP\x01\x00",
            );
        }
    });
    origin
}

#[test]
fn broken_consume_response_says_result_unknown() {
    let origin = truncating_server();
    let v = vector("plain-ascii");
    let r = sdrop(
        &origin,
        &[
            "get",
            &format!("{origin}/s/{ID}#{}", v["k_url"].as_str().unwrap()),
        ],
        b"",
    );
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("result is unknown"), "{}", r.stderr);
    assert!(r.stderr.contains("ask the sender"), "{}", r.stderr);
}

#[test]
fn stdout_and_stderr_failure_after_consume_keeps_secret() {
    let v = vector("plain-ascii");
    let f = serving_with_limit(hex(v["envelope_hex"].as_str().unwrap()), 262144);
    let target = std::env::temp_dir().join(format!("sdrop-both-{}", rand_suffix()));
    let url = format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap());
    let (code, _, _) = sdrop_closed_outputs(
        &f.origin,
        &["get", &url, "-o", "-"],
        &[target.to_str().unwrap()],
        true,
    );
    assert_eq!(code, 0);
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        v["text"].as_str().unwrap()
    );
    assert_eq!(f.requests().len(), 1);
    // Without a terminal: the default private directory, also without printing diagnostics.
    let f2 = serving_with_limit(hex(v["envelope_hex"].as_str().unwrap()), 262144);
    let url2 = format!("{}/s/{ID}#{}", f2.origin, v["k_url"].as_str().unwrap());
    let (code, _, cwd) = sdrop_closed_outputs(&f2.origin, &["get", &url2], &[], true);
    assert_eq!(code, 0);
    assert_eq!(
        std::fs::read_to_string(cwd.join(format!("sdrop-{}/data", &ID[..8]))).unwrap(),
        v["text"].as_str().unwrap()
    );
}

#[test]
fn put_fails_if_owner_link_cannot_be_written() {
    let f = Fake::start(Box::new(created(String::new())));
    let mut child = Command::new(env!("CARGO_BIN_EXE_sdrop"))
        .args(["put"])
        .env_clear()
        .envs(platform_env())
        .env("SDROP_ORIGIN", &f.origin)
        .env("SDROP_TEST_ACCESS_TOKEN", TEST_TOKEN)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stderr.take());
    child.stdin.take().unwrap().write_all(b"x").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("/s/"));
}

// ---------- Text and several files (FORMAT.md 4, README) ----------

/// File with the given name in a fresh temporary directory.
fn named_file(name: &str, content: &[u8]) -> String {
    let dir = std::env::temp_dir().join(format!("sdrop-n-{}", rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join(name);
    std::fs::write(&f, content).unwrap();
    f.to_str().unwrap().to_owned()
}

/// Decrypts the envelope the fake server received on create, with the key from the printed link.
fn sent_secret(f: &Fake, stdout: &str) -> (u8, sdrop::format::Secret) {
    let reqs = f.requests();
    let body = &reqs.last().unwrap().body;
    let key = sdrop::format::decode_key(stdout.trim_end().split('#').nth(1).unwrap()).unwrap();
    (body[4], sdrop::format::decrypt(body, &key, None).unwrap())
}

#[test]
fn put_text_and_files_makes_bundle_in_version_2() {
    let f = serving_with_limit(vec![], 262144);
    let a = named_file("prod.crt", b"CERT");
    let b = named_file("prod.key", &[0, 1, 2]);
    let note = named_file("note.txt", "ключ и сертификат".as_bytes());
    let r = sdrop(&f.origin, &["put", "--file", &a, "--file", &b, &note], b"");
    assert_eq!(r.code, 0, "{}", r.stderr);
    match sent_secret(&f, &r.stdout) {
        (2, sdrop::format::Secret::Bundle { text, files }) => {
            assert_eq!(text.as_str(), "ключ и сертификат");
            let got: Vec<_> = files
                .iter()
                .map(|(n, d)| (n.as_str(), d.to_vec()))
                .collect();
            assert_eq!(
                got,
                [("prod.crt", b"CERT".to_vec()), ("prod.key", vec![0, 1, 2])]
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn put_files_read_stdin_only_with_dash() {
    let a = named_file("a.bin", b"A");
    let b = named_file("b.bin", b"B");
    // Without INPUT the text is empty: stdin is not read.
    let f = serving_with_limit(vec![], 262144);
    let r = sdrop(&f.origin, &["put", "--file", &a, "--file", &b], b"ignored");
    assert_eq!(r.code, 0, "{}", r.stderr);
    match sent_secret(&f, &r.stdout) {
        (2, sdrop::format::Secret::Bundle { text, files }) => {
            assert_eq!(text.as_str(), "");
            assert_eq!(files.len(), 2);
        }
        other => panic!("{other:?}"),
    }
    // "-" takes the text from stdin: one file with text is a bundle too.
    let f = serving_with_limit(vec![], 262144);
    let r = sdrop(&f.origin, &["put", "--file", &a, "-"], b"from stdin");
    assert_eq!(r.code, 0, "{}", r.stderr);
    match sent_secret(&f, &r.stdout) {
        (2, sdrop::format::Secret::Bundle { text, files }) => {
            assert_eq!(text.as_str(), "from stdin");
            assert_eq!(files.len(), 1);
        }
        other => panic!("{other:?}"),
    }
    // One file without text stays a version 1 file secret.
    let f = serving_with_limit(vec![], 262144);
    let r = sdrop(&f.origin, &["put", "--file", &a], b"ignored");
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(matches!(
        sent_secret(&f, &r.stdout),
        (1, sdrop::format::Secret::File { .. })
    ));
}

#[test]
fn put_21_files_fails_before_any_request() {
    let f = never_called();
    let paths: Vec<String> = (0..21)
        .map(|i| named_file(&format!("f{i}"), b"x"))
        .collect();
    let mut args = vec!["put"];
    for p in &paths {
        args.push("--file");
        args.push(p);
    }
    let r = sdrop(&f.origin, &args, b"");
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("too many files"), "{}", r.stderr);
    assert_eq!(f.requests().len(), 0);
}

fn bundle_vector() -> (String, Vec<u8>, String, Vec<Vec<u8>>) {
    let v = vector("bundle-text-two-files");
    let b = &v["bundle"];
    (
        v["k_url"].as_str().unwrap().to_owned(),
        hex(v["envelope_hex"].as_str().unwrap()),
        b["text"].as_str().unwrap().to_owned(),
        b["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| hex(f["data_hex"].as_str().unwrap()))
            .collect(),
    )
}

#[test]
#[cfg(unix)]
fn get_bundle_text_to_stdout_files_to_private_dir() {
    let (k, env, text, datas) = bundle_vector();
    for out in [None, Some("-")] {
        let f = serving_with_limit(env.clone(), 262144);
        let url = format!("{}/s/{ID}#{k}", f.origin);
        let mut args = vec!["get", url.as_str()];
        if let Some(o) = out {
            args.extend(["-o", o]);
        }
        let r = sdrop(&f.origin, &args, b"");
        assert_eq!(r.code, 0, "{}", r.stderr);
        assert_eq!(r.stdout, text);
        let dir = r.cwd.join(format!("sdrop-{}", &ID[..8]));
        assert_eq!(mode(&dir), 0o700);
        for (i, d) in datas.iter().enumerate() {
            let p = dir.join(format!("file-{}", i + 1));
            assert_eq!(mode(&p), 0o600);
            assert_eq!(&std::fs::read(&p).unwrap(), d);
        }
        assert!(!dir.join("text").exists());
        assert!(
            r.stderr.contains("prod.crt") && r.stderr.contains("prod.key"),
            "{}",
            r.stderr
        );
        assert_eq!(f.requests().len(), 1);
    }
}

#[test]
#[cfg(unix)]
fn get_bundle_output_is_a_new_private_directory() {
    let (k, env, text, datas) = bundle_vector();
    let f = serving_with_limit(env, 262144);
    let base = std::env::temp_dir().join(format!("sdrop-bo-{}", rand_suffix()));
    std::fs::create_dir_all(&base).unwrap();
    let out = base.join("got");
    let url = format!("{}/s/{ID}#{k}", f.origin);
    let r = sdrop(&f.origin, &["get", &url, "-o", out.to_str().unwrap()], b"");
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, "");
    assert_eq!(mode(&out), 0o700);
    assert_eq!(std::fs::read_to_string(out.join("text")).unwrap(), text);
    for (i, d) in datas.iter().enumerate() {
        assert_eq!(
            &std::fs::read(out.join(format!("file-{}", i + 1))).unwrap(),
            d
        );
    }
}

#[test]
#[cfg(unix)]
fn get_bundle_write_failure_keeps_secret_and_asks_again() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe_is_root() {
        return;
    }
    let (k, env, text, datas) = bundle_vector();
    let ro = std::env::temp_dir().join(format!("sdrop-bro-{}", rand_suffix()));
    std::fs::create_dir_all(&ro).unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
    let ok = std::env::temp_dir().join(format!("sdrop-bok-{}", rand_suffix()));
    std::fs::create_dir_all(&ok).unwrap();
    let target = ok.join("saved");
    // With a terminal: another directory, same contents, one consume.
    let f = serving_with_limit(env.clone(), 262144);
    let url = format!("{}/s/{ID}#{k}", f.origin);
    let r = sdrop_tty(
        &f.origin,
        &["get", &url, "-o", ro.join("x").to_str().unwrap()],
        b"",
        Some(&["", target.to_str().unwrap()]),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stderr.contains("kept in memory"), "{}", r.stderr);
    assert_eq!(std::fs::read_to_string(target.join("text")).unwrap(), text);
    assert_eq!(std::fs::read(target.join("file-2")).unwrap(), datas[1]);
    assert_eq!(f.requests().len(), 1);
    // Without a terminal: the default private directory.
    let f2 = serving_with_limit(env, 262144);
    let url2 = format!("{}/s/{ID}#{k}", f2.origin);
    let r = sdrop(
        &f2.origin,
        &["get", &url2, "-o", ro.join("y").to_str().unwrap()],
        b"",
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let dir = r.cwd.join(format!("sdrop-{}", &ID[..8]));
    assert_eq!(std::fs::read_to_string(dir.join("text")).unwrap(), text);
    assert_eq!(std::fs::read(dir.join("file-1")).unwrap(), datas[0]);
    assert_eq!(f2.requests().len(), 1);
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
#[cfg(unix)]
fn get_bundle_stdout_failure_saves_text_with_files() {
    let (k, env, text, datas) = bundle_vector();
    let f = serving_with_limit(env, 262144);
    let url = format!("{}/s/{ID}#{k}", f.origin);
    let (code, stderr, cwd) = sdrop_closed_stdout(&f.origin, &["get", &url], &[]);
    assert_eq!(code, 0, "{stderr}");
    let dir = cwd.join(format!("sdrop-{}", &ID[..8]));
    assert_eq!(std::fs::read_to_string(dir.join("text")).unwrap(), text);
    for (i, d) in datas.iter().enumerate() {
        assert_eq!(
            &std::fs::read(dir.join(format!("file-{}", i + 1))).unwrap(),
            d
        );
    }
    assert!(stderr.contains("saved with the files"), "{stderr}");
    assert_eq!(f.requests().len(), 1);
}

#[test]
#[cfg(unix)]
fn get_bundle_partial_write_leaves_nothing_behind() {
    // file-2 is larger than the file size limit: text and file-1 get written, file-2 fails
    // (SIGXFSZ ignored -> EFBIG). Every attempt must remove what it wrote.
    let v = vector("plain-ascii");
    let k = sdrop::format::decode_key(v["k_url"].as_str().unwrap()).unwrap();
    let small = [1u8; 100];
    let big = vec![2u8; 10_000];
    let env = sdrop::format::encrypt_with(
        &sdrop::format::Content::Bundle {
            text: "note",
            files: vec![("small.bin", &small[..]), ("big.bin", &big[..])],
        },
        &k,
        &[1; 16],
        &[2; 12],
        None,
        262144,
    )
    .unwrap();
    let f = serving_with_limit(env, 262144);
    let url = format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap());
    let (dir, _) = fake_cloudflared();
    let cwd = dir.join("cwd");
    std::fs::create_dir_all(&cwd).unwrap();
    let out_dir = dir.join("out");
    let out = Command::new("sh")
        .arg("-c")
        .arg("trap '' XFSZ; ulimit -f 4; exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_sdrop"))
        .args(["get", &url, "-o", out_dir.to_str().unwrap()])
        .current_dir(&cwd)
        .env_clear()
        .envs(platform_env())
        .env("SDROP_ORIGIN", &f.origin)
        .env("SDROP_TEST_ACCESS_TOKEN", TEST_TOKEN)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("Cannot write"), "{stderr}");
    assert!(stderr.contains("could not save"), "{stderr}");
    // Neither the -o directory nor the default one is left half-written.
    assert!(!out_dir.exists());
    assert_eq!(std::fs::read_dir(&cwd).unwrap().count(), 0);
    assert_eq!(f.requests().len(), 1);
}

#[test]
fn local_checks_come_before_reading_the_access_token() {
    // An unusable Access token is reported only when a request is about to be sent: a broken link
    // or a bad -o path is reported first, as the CLI always did.
    let f = never_called();
    let existing = temp_file(b"keep");
    let cases: [(&[&str], &str); 4] = [
        (&["get", "http://127.0.0.1:1/s/zz#k"], "the link is not for"),
        (&["status", "x"], ""),
        (&["revoke", "x"], ""),
        (&["get", "-o", &existing, "PLACEHOLDER"], "already exists"),
    ];
    for (args, want) in cases {
        let url = format!("{}/s/{ID}#{}", f.origin, "A".repeat(43));
        let args: Vec<&str> = args
            .iter()
            .map(|a| if *a == "PLACEHOLDER" { url.as_str() } else { a })
            .collect();
        let out = Command::new(env!("CARGO_BIN_EXE_sdrop"))
            .args(&args)
            .env_clear()
            .envs(platform_env())
            .env("SDROP_ORIGIN", &f.origin)
            .env("SDROP_TEST_ACCESS_TOKEN", "bad token with spaces")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_ne!(out.status.code(), Some(0), "{args:?}");
        assert!(!stderr.contains("invalid characters"), "{args:?}: {stderr}");
        assert!(stderr.contains(want), "{args:?}: {stderr}");
    }
    assert_eq!(f.requests().len(), 0);
}

// ---------- Interactive mode: New secret (README, "Interactive mode") ----------

mod tui_create {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use sdrop::tui::app::{App, NewFocus, Screen};
    use sdrop::tui::clipboard::{Clip, Unavailable, Via};
    use zeroize::Zeroizing;

    struct NoClip;
    impl Clip for NoClip {
        fn copy(&mut self, _: &str) -> Result<Via, String> {
            Ok(Via::System)
        }
        fn read(&mut self) -> Result<Option<Zeroizing<String>>, Unavailable> {
            Ok(None)
        }
        fn clear(&mut self) -> Result<(), Unavailable> {
            Ok(())
        }
    }

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn client(f: &Fake) -> sdrop::ops::Client {
        sdrop::ops::Client::with_origin(sdrop::api::Origin::parse(&f.origin).unwrap(), false)
    }

    fn new_app() -> App {
        let mut app = App::new(Box::new(NoClip));
        app.key(key(KeyCode::Enter));
        app
    }

    fn focus(app: &mut App, to: NewFocus) {
        for _ in 0..20 {
            if let Screen::New(f) = &app.screen
                && f.focus == to
            {
                return;
            }
            app.key(key(KeyCode::Tab));
        }
        panic!("focus {to:?} not reached");
    }

    fn created(app: &App) -> (String, String) {
        match &app.screen {
            Screen::Created(v) => (v.recipient.to_string(), v.owner.to_string()),
            _ => panic!("not created: {:?}", app.message),
        }
    }

    #[test]
    fn text_creates_one_secret_with_cli_links() {
        let f = serving_with_limit(vec![], 262144);
        let mut c = client(&f);
        let mut app = new_app();
        app.paste("hello tui\nline 2");
        focus(&mut app, NewFocus::Create);
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        let (recipient, owner) = created(&app);
        assert!(
            recipient.starts_with(&format!("{}/s/{ID}#", f.origin)),
            "{recipient}"
        );
        assert!(
            owner.starts_with(&format!("{}/o/{ID}#", f.origin)),
            "{owner}"
        );
        let reqs = f.requests();
        assert_eq!(
            reqs.iter().map(|q| q.path.as_str()).collect::<Vec<_>>(),
            ["/api/limits", "/api/secrets?ttl=86400"]
        );
        let k = sdrop::format::decode_key(recipient.split('#').nth(1).unwrap()).unwrap();
        assert_eq!(
            sdrop::format::decrypt(&reqs[1].body, &k, None).unwrap(),
            sdrop::format::Secret::Text("hello tui\nline 2".to_string().into())
        );
    }

    #[test]
    fn passphrase_and_ttl_reach_the_link_and_envelope() {
        let f = serving_with_limit(vec![], 262144);
        let mut c = client(&f);
        let mut app = new_app();
        app.paste("with phrase");
        focus(&mut app, NewFocus::Ttl);
        app.key(key(KeyCode::Left));
        focus(&mut app, NewFocus::UsePass);
        app.key(key(KeyCode::Char(' ')));
        focus(&mut app, NewFocus::Pass);
        app.paste("пароль");
        focus(&mut app, NewFocus::Create);
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        let (recipient, _) = created(&app);
        assert!(recipient.ends_with("~p"), "{recipient}");
        let reqs = f.requests();
        assert_eq!(reqs[1].path, "/api/secrets?ttl=3600");
        let frag = recipient.split('#').nth(1).unwrap().trim_end_matches("~p");
        let k = sdrop::format::decode_key(frag).unwrap();
        assert_eq!(
            sdrop::format::decrypt(&reqs[1].body, &k, Some("пароль")).unwrap(),
            sdrop::format::Secret::Text("with phrase".to_string().into())
        );
    }

    #[test]
    fn text_and_files_make_a_bundle() {
        let f = serving_with_limit(vec![], 262144);
        let mut c = client(&f);
        let mut app = new_app();
        app.paste("note");
        for (name, data) in [("a.crt", b"CRT".as_slice()), ("b.key", b"KEY".as_slice())] {
            focus(&mut app, NewFocus::Path);
            app.paste(&named_file(name, data));
            app.key(key(KeyCode::Enter));
        }
        focus(&mut app, NewFocus::Create);
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        let (recipient, _) = created(&app);
        let reqs = f.requests();
        assert_eq!(reqs[1].body[4], 2, "bundle in envelope version 2");
        let k = sdrop::format::decode_key(recipient.split('#').nth(1).unwrap()).unwrap();
        match sdrop::format::decrypt(&reqs[1].body, &k, None).unwrap() {
            sdrop::format::Secret::Bundle { text, files } => {
                assert_eq!(text.as_str(), "note");
                let got: Vec<_> = files
                    .iter()
                    .map(|(n, d)| (n.as_str(), d.to_vec()))
                    .collect();
                assert_eq!(
                    got,
                    [("a.crt", b"CRT".to_vec()), ("b.key", b"KEY".to_vec())]
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn too_many_files_and_over_limit_send_nothing() {
        let f = serving_with_limit(vec![], 65536);
        let mut c = client(&f);
        let mut app = new_app();
        for i in 0..21 {
            focus(&mut app, NewFocus::Path);
            app.paste(&named_file(&format!("f{i}"), b"x"));
            app.key(key(KeyCode::Enter));
        }
        let Screen::New(form) = &app.screen else {
            panic!()
        };
        assert_eq!(form.files.len(), 20);
        assert!(app.message.as_ref().unwrap().1.contains("at most 20"));
        // Over the service limit: only the limit is asked, nothing is created.
        let mut app = new_app();
        focus(&mut app, NewFocus::Path);
        app.paste(&named_file("big.bin", &vec![7u8; 100_000]));
        app.key(key(KeyCode::Enter));
        focus(&mut app, NewFocus::Create);
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert!(matches!(app.screen, Screen::New(_)));
        assert!(
            app.message.as_ref().unwrap().1.contains("limit of 64 KB"),
            "{:?}",
            app.message
        );
        assert_eq!(
            f.requests()
                .iter()
                .map(|q| q.path.as_str())
                .collect::<Vec<_>>(),
            ["/api/limits"]
        );
    }
}

// ---------- Interactive mode: Open a link, Check status ----------

mod tui_open {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use sdrop::tui::app::{Action, App, Hit, Screen};
    use sdrop::tui::clipboard::{Clip, Unavailable, Via};
    use std::sync::{Arc, Mutex};
    use zeroize::Zeroizing;

    #[derive(Clone, Default)]
    struct MemClip(Arc<Mutex<Option<String>>>);
    impl Clip for MemClip {
        fn copy(&mut self, t: &str) -> Result<Via, String> {
            *self.0.lock().unwrap() = Some(t.to_owned());
            Ok(Via::System)
        }
        fn read(&mut self) -> Result<Option<Zeroizing<String>>, Unavailable> {
            Ok(self.0.lock().unwrap().clone().map(Zeroizing::new))
        }
        fn clear(&mut self) -> Result<(), Unavailable> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn client(f: &Fake) -> sdrop::ops::Client {
        sdrop::ops::Client::with_origin(sdrop::api::Origin::parse(&f.origin).unwrap(), false)
    }

    /// App on the "Open a link" screen with the link pasted and checked.
    fn opened(link: &str, c: &mut sdrop::ops::Client, clip: MemClip) -> App {
        let mut app = App::new(Box::new(clip));
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Enter));
        app.paste(link);
        app.key(key(KeyCode::Enter));
        app.perform(c);
        app
    }

    /// Draw a frame at `w`×`h` (records the click areas).
    fn draw_at(app: &App, w: u16, h: u16) -> String {
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
        t.draw(|f| app.render(f)).unwrap();
        t.backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    fn draw(app: &App) -> String {
        draw_at(app, 80, 24)
    }

    fn click(app: &mut App, column: u16, row: u16) {
        app.mouse(crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        });
    }

    fn revealed_text(app: &App) -> String {
        match &app.screen {
            Screen::Revealed(v) => v.text().to_owned(),
            _ => panic!("not revealed: {:?}", app.message),
        }
    }

    #[test]
    fn broken_or_foreign_link_sends_nothing() {
        let f = never_called();
        let mut c = client(&f);
        for link in [
            "garbage".to_string(),
            format!("{}/s/{ID}#short", f.origin),
            format!("https://evil.example/s/{ID}#{}", "A".repeat(43)),
        ] {
            let app = opened(&link, &mut c, MemClip::default());
            assert!(matches!(app.screen, Screen::Open(_)), "{link}");
            assert!(app.message.as_ref().unwrap().0, "{link}: an error is shown");
        }
        assert_eq!(f.requests().len(), 0);
    }

    #[test]
    fn wrong_kind_of_link_explains_and_sends_nothing() {
        let f = never_called();
        let mut c = client(&f);
        let k43 = "A".repeat(43);
        // A recipient link pasted into Check status: never consumed, the message says what to use.
        let mut app = App::new(Box::new(MemClip::default()));
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Enter));
        app.paste(&format!("{}/s/{ID}#{k43}", f.origin));
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert!(matches!(app.screen, Screen::StatusForm(_)));
        assert!(
            app.message.as_ref().unwrap().1.contains("recipient link"),
            "{:?}",
            app.message
        );
        // A status link pasted into Open a link.
        let app = opened(
            &format!("{}/o/{ID}#{k43}", f.origin),
            &mut c,
            MemClip::default(),
        );
        assert!(
            app.message.as_ref().unwrap().1.contains("status link"),
            "{:?}",
            app.message
        );
        assert_eq!(f.requests().len(), 0);
    }

    #[test]
    fn reveal_only_after_confirmation_exactly_one_consume() {
        let v = vector("plain-ascii");
        let f = serving_with_limit(hex(v["envelope_hex"].as_str().unwrap()), 262144);
        let mut c = client(&f);
        let link = format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap());
        let mut app = opened(&link, &mut c, MemClip::default());
        assert!(matches!(app.screen, Screen::Reveal(_)));
        assert_eq!(f.requests().len(), 0, "nothing before Reveal");
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert_eq!(revealed_text(&app), v["text"].as_str().unwrap());
        assert_eq!(f.requests().len(), 1);
        assert!(f.requests()[0].path.ends_with("/consume"));
    }

    #[test]
    fn passphrase_by_hint_before_consume() {
        let v = vector("passphrase-ascii");
        let f = serving_with_limit(hex(v["envelope_hex"].as_str().unwrap()), 262144);
        let mut c = client(&f);
        let link = format!("{}/s/{ID}#{}~p", f.origin, v["k_url"].as_str().unwrap());
        let mut app = opened(&link, &mut c, MemClip::default());
        app.key(key(KeyCode::Enter));
        assert!(app.pending.is_none(), "empty passphrase: nothing queued");
        app.paste(v["passphrase"].as_str().unwrap());
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert_eq!(revealed_text(&app), v["text"].as_str().unwrap());
        assert_eq!(f.requests().len(), 1);
    }

    #[test]
    fn passphrase_after_consume_wrong_empty_right_one_consume() {
        let v = vector("passphrase-ascii");
        let f = serving_with_limit(hex(v["envelope_hex"].as_str().unwrap()), 262144);
        let mut c = client(&f);
        // The ~p suffix was removed: the envelope flag asks for the passphrase after consume.
        let link = format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap());
        let mut app = opened(&link, &mut c, MemClip::default());
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert!(matches!(app.screen, Screen::Unlock(_)), "{:?}", app.message);
        app.paste("wrong");
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert!(matches!(app.screen, Screen::Unlock(_)));
        assert!(app.message.as_ref().unwrap().1.contains("Wrong passphrase"));
        app.key(key(KeyCode::Enter));
        assert!(
            app.pending.is_none(),
            "empty: nothing queued, envelope kept"
        );
        assert!(matches!(app.screen, Screen::Unlock(_)));
        app.paste(v["passphrase"].as_str().unwrap());
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert_eq!(revealed_text(&app), v["text"].as_str().unwrap());
        assert_eq!(f.requests().len(), 1, "every retry was local");
    }

    #[test]
    fn copy_secret_text_warns_then_copies() {
        let v = vector("plain-ascii");
        let f = serving_with_limit(hex(v["envelope_hex"].as_str().unwrap()), 262144);
        let mut c = client(&f);
        let clip = MemClip::default();
        let link = format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap());
        let mut app = opened(&link, &mut c, clip.clone());
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        app.key(key(KeyCode::Char('c')));
        assert_eq!(*clip.0.lock().unwrap(), None);
        app.key(key(KeyCode::Char('c')));
        assert_eq!(clip.0.lock().unwrap().as_deref(), v["text"].as_str());
        // Leaving the app removes the copied secret from the clipboard.
        drop(app);
        assert_eq!(*clip.0.lock().unwrap(), None);
    }

    #[test]
    #[cfg(unix)]
    fn save_fails_then_another_directory_gets_all_bytes_one_consume() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe_is_root() {
            return;
        }
        let (k, env, text, datas) = bundle_vector();
        let f = serving_with_limit(env, 262144);
        let mut c = client(&f);
        let link = format!("{}/s/{ID}#{k}", f.origin);
        let mut app = opened(&link, &mut c, MemClip::default());
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert_eq!(revealed_text(&app), text);
        // Leaving with unsaved files asks first; Esc cancels.
        app.key(key(KeyCode::Esc));
        assert!(app.dialog.is_some() && matches!(app.screen, Screen::Revealed(_)));
        app.key(key(KeyCode::Esc));
        assert!(app.dialog.is_none());
        let ro = std::env::temp_dir().join(format!("sdrop-tro-{}", rand_suffix()));
        std::fs::create_dir_all(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
        app.key(key(KeyCode::Char('s')));
        app.paste(ro.join("x").to_str().unwrap());
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert!(matches!(app.screen, Screen::Revealed(_)));
        assert!(app.message.as_ref().unwrap().1.contains("still here"));
        assert!(!ro.join("x").exists());
        let good = std::env::temp_dir().join(format!("sdrop-tok-{}", rand_suffix()));
        // Ctrl+C with unsaved files asks; Enter right away is "Stay".
        app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(!app.quit && app.dialog.is_some());
        app.key(key(KeyCode::Enter));
        assert!(!app.quit && app.dialog.is_none());
        // The failed path stays in the open field: the user erases it with Backspace and types
        // another one.
        for _ in 0..ro.join("x").to_str().unwrap().chars().count() {
            app.key(key(KeyCode::Backspace));
        }
        app.paste(good.to_str().unwrap());
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert_eq!(std::fs::read_to_string(good.join("text")).unwrap(), text);
        for (i, d) in datas.iter().enumerate() {
            assert_eq!(
                &std::fs::read(good.join(format!("file-{}", i + 1))).unwrap(),
                d
            );
        }
        assert_eq!(f.requests().len(), 1);
        // Saved: leaving does not ask.
        app.key(key(KeyCode::Esc));
        assert!(matches!(app.screen, Screen::Home { .. }));
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn status_check_and_revoke_with_confirmation() {
        let token = "B".repeat(42) + "A";
        let revoked = Arc::new(Mutex::new(false));
        let r2 = revoked.clone();
        let f = Fake::start(Box::new(move |q| match q.method.as_str() {
            "GET" => {
                let state = if *r2.lock().unwrap() {
                    "revoked"
                } else {
                    "stored"
                };
                (
                    200,
                    vec![],
                    format!(r#"{{"state":"{state}","createdAt":"c","expiresAt":"e"}}"#)
                        .into_bytes(),
                )
            }
            "DELETE" => {
                *r2.lock().unwrap() = true;
                (204, vec![], vec![])
            }
            _ => (404, vec![], vec![]),
        }));
        let mut c = client(&f);
        let mut app = App::new(Box::new(MemClip::default()));
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Enter));
        app.paste(&format!("{}/o/{ID}#{token}", f.origin));
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        let state = |app: &App| match &app.screen {
            Screen::Status(v) => v.status.state.clone(),
            _ => panic!("{:?}", app.message),
        };
        assert_eq!(state(&app), "stored");
        // x asks; Enter on the fresh dialog is Cancel.
        app.key(key(KeyCode::Char('x')));
        assert!(app.pending.is_none() && app.dialog.is_some(), "x only asks");
        app.key(key(KeyCode::Enter));
        assert!(app.pending.is_none() && app.dialog.is_none());
        app.key(key(KeyCode::Char('r')));
        app.perform(&mut c);
        // Esc, and a click outside the dialog (on the Revoke button behind it), revoke nothing.
        app.key(key(KeyCode::Char('x')));
        app.key(key(KeyCode::Esc));
        assert!(app.pending.is_none() && app.dialog.is_none());
        app.key(key(KeyCode::Char('x')));
        draw(&app);
        let behind = app
            .hits
            .borrow()
            .iter()
            .find(|(_, h)| matches!(h, Hit::Act(Action::AskRevoke, _)))
            .map(|(r, _)| *r)
            .unwrap();
        click(&mut app, behind.x, behind.y);
        assert!(app.pending.is_none() && app.dialog.is_some());
        app.key(key(KeyCode::Right));
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert_eq!(state(&app), "revoked");
        assert!(*revoked.lock().unwrap());
        app.key(key(KeyCode::Char('r')));
        app.perform(&mut c);
        let methods: Vec<_> = f.requests().iter().map(|q| q.method.clone()).collect();
        assert_eq!(methods, ["GET", "GET", "DELETE", "GET", "GET"]);
        for q in f.requests() {
            assert!(
                q.headers
                    .contains(&("authorization".into(), format!("Bearer {token}")))
            );
        }
    }
    /// After consume the envelope lives only in the passphrase screen: Discard asks, Enter right
    /// away, Esc and a click outside keep it; the window shrinking below 80×24 keeps it too. The
    /// right passphrase then decrypts it with no second consume.
    #[test]
    fn passphrase_screen_survives_dialog_and_small_window() {
        let v = vector("passphrase-ascii");
        let f = serving_with_limit(hex(v["envelope_hex"].as_str().unwrap()), 262144);
        let mut c = client(&f);
        let link = format!("{}/s/{ID}#{}", f.origin, v["k_url"].as_str().unwrap());
        let mut app = opened(&link, &mut c, MemClip::default());
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert!(matches!(app.screen, Screen::Unlock(_)));
        app.key(key(KeyCode::Esc));
        assert!(draw(&app).contains("Discard the downloaded secret?"));
        app.key(key(KeyCode::Enter));
        assert!(app.dialog.is_none() && matches!(app.screen, Screen::Unlock(_)));
        app.key(key(KeyCode::Esc));
        app.key(key(KeyCode::Esc));
        app.key(key(KeyCode::Esc));
        draw(&app);
        click(&mut app, 0, 0);
        assert!(app.dialog.is_some() && matches!(app.screen, Screen::Unlock(_)));
        app.key(key(KeyCode::Esc));
        app.paste("typed so far");
        draw_at(&app, 80, 24);
        assert!(draw_at(&app, 79, 23).contains("Enlarge the window"));
        app.key(key(KeyCode::Esc));
        app.paste("ignored while small");
        assert!(draw_at(&app, 120, 35).contains("typed so far"));
        let Screen::Unlock(u) = &mut app.screen else {
            panic!("{:?}", app.message)
        };
        u.pass.clear();
        app.paste(v["passphrase"].as_str().unwrap());
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert_eq!(revealed_text(&app), v["text"].as_str().unwrap());
        assert_eq!(f.requests().len(), 1, "one consume");
    }

    /// Received files survive 80×24 → 79×23 → 120×35 and are saved whole afterwards.
    #[test]
    fn received_files_survive_a_small_window_and_save() {
        let (k, env, text, datas) = bundle_vector();
        let f = serving_with_limit(env, 262144);
        let mut c = client(&f);
        let link = format!("{}/s/{ID}#{k}", f.origin);
        let mut app = opened(&link, &mut c, MemClip::default());
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        draw_at(&app, 80, 24);
        draw_at(&app, 79, 23);
        app.key(key(KeyCode::Esc));
        app.key(key(KeyCode::Enter));
        assert!(app.dialog.is_none() && matches!(app.screen, Screen::Revealed(_)));
        draw_at(&app, 120, 35);
        let dir = std::env::temp_dir().join(format!("sdrop-tsz-{}", rand_suffix()));
        app.key(key(KeyCode::Char('s')));
        app.paste(dir.to_str().unwrap());
        app.key(key(KeyCode::Enter));
        app.perform(&mut c);
        assert_eq!(std::fs::read_to_string(dir.join("text")).unwrap(), text);
        for (i, d) in datas.iter().enumerate() {
            assert_eq!(
                &std::fs::read(dir.join(format!("file-{}", i + 1))).unwrap(),
                d
            );
        }
        assert_eq!(f.requests().len(), 1, "one consume");
    }
}
