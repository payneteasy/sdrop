//! Shared format test vectors (FORMAT.md 7): the same files the browser client is tested with.
use sdrop::format::{self, Content, FormatError, Secret};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn load(name: &str) -> Value {
    let path = format!("{}/spec/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("файл векторов"))
        .expect("JSON векторов")
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().expect("длина поля вектора")
}

/// File data from a seed, as in scripts/gen-vectors.mjs: each 32 bytes = SHA-256(`seed/offset`).
fn seeded(seed: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        let block = Sha256::digest(format!("{seed}/{i}"));
        out.extend_from_slice(&block[..32.min(n - i)]);
        i += 32;
    }
    out
}

/// Expected secret of a vector.
enum Expected {
    Text(String),
    File(String, Vec<u8>),
    Bundle(String, Vec<(String, Vec<u8>)>),
}

/// Bytes of a vector file: `data_hex` or `data_seed` + `size`.
fn file_bytes(f: &Value) -> Vec<u8> {
    match f.get("data_hex") {
        Some(h) => hex(h.as_str().unwrap()),
        None => seeded(
            f["data_seed"].as_str().unwrap(),
            f["size"].as_u64().unwrap() as usize,
        ),
    }
}

fn expected(v: &Value) -> Expected {
    if let Some(f) = v.get("file") {
        Expected::File(f["name"].as_str().unwrap().to_owned(), file_bytes(f))
    } else if let Some(b) = v.get("bundle") {
        let files = b["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| (f["name"].as_str().unwrap().to_owned(), file_bytes(f)))
            .collect();
        Expected::Bundle(b["text"].as_str().unwrap().to_owned(), files)
    } else if let Some(r) = v.get("text_repeat") {
        Expected::Text(
            r["char"]
                .as_str()
                .unwrap()
                .repeat(r["count"].as_u64().unwrap() as usize),
        )
    } else {
        Expected::Text(v["text"].as_str().unwrap().to_owned())
    }
}

fn same(got: &Secret, want: &Expected) -> bool {
    match (got, want) {
        (Secret::Text(t), Expected::Text(w)) => t.as_str() == w,
        (Secret::File { name, data }, Expected::File(n, d)) => {
            name.as_str() == n.as_str() && data.as_slice() == d.as_slice()
        }
        (Secret::Bundle { text, files }, Expected::Bundle(t, w)) => {
            text.as_str() == t
                && files.len() == w.len()
                && files.iter().zip(w).all(|((n, d), (wn, wd))| {
                    n.as_str() == wn.as_str() && d.as_slice() == wd.as_slice()
                })
        }
        _ => false,
    }
}

#[test]
fn positive_vectors_both_directions() {
    let vectors = load("vectors.json");
    let list = vectors.as_array().unwrap();
    assert!(list.len() >= 19);
    let mut buckets = std::collections::BTreeSet::new();
    for v in list {
        let name = v["name"].as_str().unwrap();
        let k = format::decode_key(v["k_url"].as_str().unwrap()).unwrap();
        let salt: [u8; 16] = arr(&hex(v["salt"].as_str().unwrap()));
        let iv: [u8; 12] = arr(&hex(v["iv"].as_str().unwrap()));
        let pass = v["passphrase"].as_str();
        let want = expected(v);
        let content = match &want {
            Expected::Text(t) => Content::Text(t),
            Expected::File(n, d) => Content::File { name: n, data: d },
            Expected::Bundle(t, f) => Content::Bundle {
                text: t,
                files: f.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect(),
            },
        };
        let bucket = v["bucket"].as_u64().unwrap() as usize;
        buckets.insert(bucket);
        let env = format::encrypt_with(&content, &k, &salt, &iv, pass, format::MAX_BUCKET)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(env.len(), 34 + bucket + 16, "{name}");
        // Section 3.3a: bundle goes in envelope version 2, text and file in version 1.
        let version = if matches!(want, Expected::Bundle(..)) {
            2
        } else {
            1
        };
        assert_eq!(env[4], version, "{name}");
        let stored = match v.get("envelope_hex") {
            Some(h) => {
                assert_eq!(to_hex(&env), h.as_str().unwrap(), "шифрование {name}");
                hex(h.as_str().unwrap())
            }
            None => {
                assert_eq!(
                    to_hex(&Sha256::digest(&env)),
                    v["envelope_sha256"].as_str().unwrap(),
                    "шифрование {name}"
                );
                env.clone()
            }
        };
        let got = format::decrypt(&stored, &k, pass).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(same(&got, &want), "расшифровка {name}");
    }
    assert_eq!(
        buckets.into_iter().collect::<Vec<_>>(),
        vec![1024, 4096, 16384, 65536, 262144, 1048576]
    );
}

#[test]
fn nfc_and_nfd_give_same_envelope() {
    let vectors = load("vectors.json");
    let find = |n: &str| {
        vectors
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == n)
            .unwrap()
            .clone()
    };
    let (a, b) = (find("passphrase-nfc"), find("passphrase-nfd"));
    assert_ne!(a["passphrase"], b["passphrase"]);
    assert_eq!(a["envelope_hex"], b["envelope_hex"]);
}

#[test]
fn passphrase_ignored_without_flag() {
    let vectors = load("vectors.json");
    let v = vectors
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "plain-ascii")
        .unwrap();
    let k = format::decode_key(v["k_url"].as_str().unwrap()).unwrap();
    let got = format::decrypt(
        &hex(v["envelope_hex"].as_str().unwrap()),
        &k,
        Some("лишняя"),
    )
    .unwrap();
    assert!(same(&got, &expected(v)));
}

#[test]
fn negative_vectors_rejected_with_same_codes() {
    let invalid = load("vectors-invalid.json");
    let list = invalid.as_array().unwrap();
    assert!(list.len() > 40);
    for v in list {
        let name = v["name"].as_str().unwrap();
        let k = format::decode_key(v["k_url"].as_str().unwrap()).unwrap();
        let err = format::decrypt(
            &hex(v["envelope_hex"].as_str().unwrap()),
            &k,
            v["passphrase"].as_str(),
        )
        .err()
        .unwrap_or_else(|| panic!("{name}: принят"));
        assert_eq!(err.code(), v["error"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn links_parsed_like_js() {
    let links = load("links.json");
    for l in links["valid"].as_array().unwrap() {
        let (k, hint) = format::parse_recipient_fragment(l["fragment"].as_str().unwrap()).unwrap();
        assert_eq!(to_hex(&*k), l["key_hex"].as_str().unwrap());
        assert_eq!(hint, l["passphrase_hint"].as_bool().unwrap());
    }
    for l in links["invalid"].as_array().unwrap() {
        let r = format::parse_recipient_fragment(l["fragment"].as_str().unwrap());
        assert_eq!(r.err(), Some(FormatError::BadLink), "{}", l["name"]);
    }
}

#[test]
fn owner_fragment() {
    let t = format::encode_base64url(&[7u8; 32]);
    assert_eq!(format::parse_owner_fragment(&t).unwrap().as_str(), t);
    assert!(format::parse_owner_fragment(&format!("{t}~p")).is_err());
    assert!(format::parse_owner_fragment(&format!("{}B", "A".repeat(42))).is_err());
}

/// Escaping per the text of FORMAT.md 3, written independently of serde_json.
fn spec_escape(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[test]
fn canonical_escaping_matches_spec() {
    let mut samples: Vec<String> = (0u32..=0xff)
        .map(|c| char::from_u32(c).unwrap().to_string())
        .collect();
    for s in [
        "я",
        "€",
        "\u{2028}",
        "\u{2029}",
        "\u{feff}",
        "🔐",
        "</script>",
        "/",
    ] {
        samples.push(s.to_string());
    }
    for s in samples {
        let plain = format::encode_plaintext(&Content::Text(&s), format::MAX_BUCKET).unwrap();
        let len = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
        let json = std::str::from_utf8(&plain[4..4 + len]).unwrap();
        assert_eq!(
            json,
            format!(r#"{{"kind":"text","text":{}}}"#, spec_escape(&s)),
            "{s:?}"
        );
        assert_eq!(
            format::decode_plaintext(&plain, format::VERSION).unwrap(),
            Secret::Text(s.clone().into())
        );
    }
}

#[test]
fn creation_errors() {
    let text =
        |t: &str, max: usize| format::encode_plaintext(&Content::Text(t), max).map(|p| p.len());
    assert_eq!(
        text("", format::MAX_BUCKET).err(),
        Some(FormatError::EmptyText)
    );
    assert_eq!(
        text(&"a".repeat(1048548), format::MAX_BUCKET).err(),
        Some(FormatError::TooLarge)
    );
    assert_eq!(
        text(&"a".repeat(65508), 65536).err(),
        Some(FormatError::TooLarge)
    );
    assert_eq!(text(&"a".repeat(65507), 65536), Ok(65536));
    assert_eq!(text(&"a".repeat(65508), format::MAX_BUCKET), Ok(262144));
    let file = |n: &str, len: usize, max: usize| {
        let d = vec![1u8; len];
        format::encode_plaintext(&Content::File { name: n, data: &d }, max).map(|p| p.len())
    };
    assert_eq!(
        file("a", 0, format::MAX_BUCKET).err(),
        Some(FormatError::EmptyFile)
    );
    for bad in [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "a\u{0}",
        "a\u{7f}",
        &"x".repeat(256),
    ] {
        assert_eq!(
            file(bad, 1, format::MAX_BUCKET).err(),
            Some(FormatError::BadName),
            "{bad:?}"
        );
    }
    assert_eq!(file("a", 262144, 262144).err(), Some(FormatError::TooLarge));
    assert_eq!(file(&"я".repeat(127), 1, format::MAX_BUCKET), Ok(1024));
    let z = [0u8; 32];
    assert_eq!(
        format::encrypt_with(
            &Content::Text("a"),
            &z,
            &[0; 16],
            &[0; 12],
            Some(""),
            format::MAX_BUCKET
        )
        .err(),
        Some(FormatError::EmptyPassphrase)
    );
}

#[test]
fn sanitize_file_name_like_js() {
    assert_eq!(format::sanitize_file_name("C:\\dir\\a\u{7}.txt"), "a_.txt");
    assert_eq!(format::sanitize_file_name("/etc/passwd"), "passwd");
    for n in ["", ".", "..", "dir/"] {
        assert_eq!(format::sanitize_file_name(n), "file");
    }
    assert!(format::sanitize_file_name(&"я".repeat(200)).len() <= 255);
}

#[test]
fn random_roundtrip_with_and_without_passphrase() {
    for pass in [None, Some("pw")] {
        let (env, k) = format::encrypt(&Content::Text("секрет"), pass, format::MAX_BUCKET).unwrap();
        assert_eq!(format::inspect_envelope(&env).unwrap(), pass.is_some());
        assert_eq!(
            format::decrypt(&env, &k, pass).unwrap(),
            Secret::Text("секрет".to_string().into())
        );
    }
    let (a, ka) = format::encrypt(&Content::Text("x"), None, format::MAX_BUCKET).unwrap();
    let (b, kb) = format::encrypt(&Content::Text("x"), None, format::MAX_BUCKET).unwrap();
    assert_ne!(a, b);
    assert_ne!(*ka, *kb);
}

#[test]
fn bundle_compose_and_encode_errors() {
    let d = [7u8; 4];
    let one = vec![("a", &d[..])];
    assert!(matches!(format::compose("t", vec![]), Content::Text(_)));
    assert!(matches!(
        format::compose("", one.clone()),
        Content::File { .. }
    ));
    assert!(matches!(
        format::compose("t", one.clone()),
        Content::Bundle { .. }
    ));
    assert_eq!(format::version_of(&format::compose("t", one.clone())), 2);
    assert_eq!(format::version_of(&format::compose("t", vec![])), 1);
    let enc = |text: &str, files: Vec<(&str, &[u8])>| {
        format::encode_plaintext(&Content::Bundle { text, files }, format::MAX_BUCKET)
            .map(|p| p.len())
    };
    assert_eq!(enc("t", vec![]), Err(FormatError::Corrupt));
    assert_eq!(enc("", one.clone()), Err(FormatError::Corrupt));
    let names: Vec<String> = (0..21).map(|i| format!("f{i}")).collect();
    let many = |n: usize| {
        names[..n]
            .iter()
            .map(|s| (s.as_str(), &d[..]))
            .collect::<Vec<_>>()
    };
    assert_eq!(enc("t", many(21)), Err(FormatError::TooManyFiles));
    assert_eq!(enc("t", many(20)), Ok(1024));
    assert_eq!(
        enc("t", vec![("a", &d[..]), ("b", &[][..])]),
        Err(FormatError::EmptyFile)
    );
    assert_eq!(
        enc("t", vec![("a", &d[..]), ("a/b", &d[..])]),
        Err(FormatError::BadName)
    );
    let big = vec![1u8; 200_000];
    let big2 = vec![2u8; 70_000];
    assert_eq!(
        format::encode_plaintext(
            &Content::Bundle {
                text: "t",
                files: vec![("a", &big[..]), ("b", &big2[..])]
            },
            262144
        ),
        Err(FormatError::TooLarge)
    );
}

#[test]
fn decode_plaintext_only_versions_1_and_2() {
    let plain = format::encode_plaintext(&Content::Text("a"), format::MAX_BUCKET).unwrap();
    assert_eq!(
        format::decode_plaintext(&plain, 1).unwrap(),
        Secret::Text("a".to_string().into())
    );
    for v in [0u8, 2, 3, 255] {
        assert_eq!(
            format::decode_plaintext(&plain, v),
            Err(FormatError::Corrupt),
            "{v}"
        );
    }
}

#[test]
fn plaintext_len_matches_the_encoding() {
    type Files<'a> = Vec<(&'a str, &'a [u8])>;
    let d1 = vec![7u8; 1234];
    let d2 = [8u8; 5];
    let cases: Vec<(&str, Files)> = vec![
        ("hello \"world\"\n\u{1}", vec![]),
        ("", vec![("key.pem", &d1[..])]),
        ("note", vec![("ключ.pem", &d1[..])]),
        ("", vec![("a", &d1[..]), ("b\"c", &d2[..])]),
        (
            "текст 🔐",
            vec![("a", &d1[..]), ("b", &d2[..]), ("c", &d2[..])],
        ),
    ];
    for (text, files) in cases {
        let sizes: Vec<(&str, usize)> = files.iter().map(|(n, d)| (*n, d.len())).collect();
        let plain =
            format::encode_plaintext(&format::compose(text, files.clone()), format::MAX_BUCKET)
                .unwrap();
        let header = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
        let data: usize = sizes.iter().map(|(_, z)| z).sum();
        assert_eq!(
            format::plaintext_len(text, &sizes),
            4 + header + data,
            "{text:?}"
        );
    }
}

#[test]
fn bundle_names_that_look_like_the_list_roundtrip() {
    let names = [
        r#"a},{"name":"b"#,
        r#"x","size":1}]}"#,
        "q\"u\"o\"te",
        "brace}",
        "comma,",
        "ключ 🔐.pem",
    ];
    let data = [1u8, 2, 3];
    let files: Vec<(&str, &[u8])> = names.iter().map(|n| (*n, &data[..])).collect();
    let plain = format::encode_plaintext(&format::compose("t", files), format::MAX_BUCKET).unwrap();
    match format::decode_plaintext(&plain, 2).unwrap() {
        Secret::Bundle { text, files } => {
            assert_eq!(text.as_str(), "t");
            let got: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(got, names);
            assert!(files.iter().all(|(_, d)| d.as_slice() == data));
        }
        other => panic!("{other:?}"),
    }
}
