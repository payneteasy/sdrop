#!/usr/bin/env node
// A minimal Payneteasy Secrets client in plain JavaScript: Node.js 20 or later, no dependencies
// (WebCrypto, fetch and String.prototype.normalize are built in). It follows FORMAT.md and is a
// starting point for your own client, not a replacement for `sdrop`.
//
//   node sdrop-client.mjs selftest [spec-dir]    check against the shared test vectors
//   echo "text" | node sdrop-client.mjs put [--ttl 3600|86400|604800] [file ...]
//   node sdrop-client.mjs get                    the recipient link from stdin
//   node sdrop-client.mjs status | revoke        the sender link from stdin
//
// Links, passphrases and tokens are never command-line arguments (other users can see them in
// the process list). Environment: SDROP_ORIGIN (https://secrets.example.com), SDROP_PASSPHRASE
// (optional; else asked on the terminal without echo), SDROP_ACCESS_TOKEN (only for a service
// behind Cloudflare Access).

import { mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { StringDecoder } from "node:string_decoder";
import tty from "node:tty";

const { subtle } = globalThis.crypto;
const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

// ---------- Format (FORMAT.md 1-5) ----------

const MAGIC = [0x53, 0x44, 0x52, 0x50]; // "SDRP"
const HEADER_LEN = 34;
const TAG_LEN = 16;
const BUCKETS = [1024, 4096, 16384, 65536, 262144, 1048576];
const ENVELOPE_LENGTHS = BUCKETS.map((b) => HEADER_LEN + b + TAG_LEN);
const MAX_FILES = 20;
const PBKDF2_ITERATIONS = 600000;
const HKDF_INFO = new TextEncoder().encode("secret-drop v1 aes-256-gcm");
const FLAG_PASSPHRASE = 1;
const TTLS = [3600, 86400, 604800];

const utf8 = new TextEncoder();
// fatal: invalid UTF-8 is an error; ignoreBOM: a BOM is kept, so it fails the prefix check.
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Error codes as in the test vectors: corrupt, decrypt_failed, need_passphrase; and bad_link,
 * bad_name, empty_text, empty_file, empty_passphrase, too_large, too_many_files. */
export class FormatError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
const fail = (code) => {
  throw new FormatError(code);
};

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");

/** 43 base64url characters → exactly 32 bytes that encode back to the same string. */
export function decodeKey(s) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(s)) fail("bad_link");
  const key = new Uint8Array(Buffer.from(s, "base64url"));
  if (key.length !== 32 || b64url(key) !== s) fail("bad_link");
  return key;
}

/** Recipient fragment: the key and the `~p` hint. */
export function parseRecipientFragment(fragment) {
  const hint = fragment.endsWith("~p");
  return { key: decodeKey(hint ? fragment.slice(0, -2) : fragment), passphraseHint: hint };
}

/** `<origin>/s/<id>#<K_url>[~p]` or `<origin>/o/<id>#<ownerToken>`, only for the trusted origin. */
export function parseLink(link, origin, kind) {
  const m = /^(.*)\/([so])\/([0-9a-f]{64})#(.*)$/s.exec(link.trim());
  if (!m || m[1] !== origin || m[2] !== kind) fail("bad_link");
  const id = m[3];
  if (kind === "s") return { id, ...parseRecipientFragment(m[4]) };
  decodeKey(m[4]);
  return { id, ownerToken: m[4] };
}

/** Canonical JSON string (FORMAT.md 3): JSON.stringify of a well-formed string. */
function jsonString(s) {
  if (!s.isWellFormed()) fail("corrupt");
  return JSON.stringify(s);
}

export function validName(name) {
  return (
    typeof name === "string" &&
    name.isWellFormed() &&
    name.length > 0 &&
    utf8.encode(name).length <= 255 &&
    name !== "." &&
    name !== ".." &&
    !/[\u0000-\u001f\u007f/\\]/.test(name)
  );
}

/** Base name with forbidden characters replaced, as the reference clients send it. */
export function sanitizeName(path) {
  let name = path.split(/[/\\]/).pop().replace(/[\u0000-\u001f\u007f]/g, "_");
  while (utf8.encode(name).length > 255) name = [...name].slice(0, -1).join("");
  return name === "" || name === "." || name === ".." ? "file" : name;
}

/**
 * The one record (FORMAT.md 3, 4): no files → text (v1); one file and no text → file (v1);
 * otherwise bundle (v2). `files`: [{ name, data: Uint8Array }]. Returns the padded plaintext.
 */
export function encodePlaintext(text, files, maxBucket = 1048576) {
  if (files.length > MAX_FILES) fail("too_many_files");
  for (const f of files) {
    if (!validName(f.name)) fail("bad_name");
    if (f.data.length === 0) fail("empty_file");
  }
  let json;
  let version = 1;
  if (files.length === 0) {
    if (text === "") fail("empty_text");
    json = `{"kind":"text","text":${jsonString(text)}}`;
  } else if (files.length === 1 && text === "") {
    json = `{"kind":"file","name":${jsonString(files[0].name)},"size":${files[0].data.length}}`;
  } else {
    version = 2;
    const list = files.map((f) => `{"name":${jsonString(f.name)},"size":${f.data.length}}`);
    json = `{"kind":"bundle","text":${jsonString(text)},"files":[${list.join(",")}]}`;
  }
  const header = utf8.encode(json);
  const need = 4 + header.length + files.reduce((n, f) => n + f.data.length, 0);
  const bucket = BUCKETS.find((b) => b >= need);
  if (!bucket || bucket > maxBucket) fail("too_large");
  const plain = new Uint8Array(bucket); // zeros up to the bucket
  new DataView(plain.buffer).setUint32(0, header.length);
  plain.set(header, 4);
  let at = 4 + header.length;
  for (const f of files) {
    plain.set(f.data, at);
    at += f.data.length;
  }
  return { plain, version };
}

/** A JSON string literal accepted only in its canonical form. */
function canonicalString(lit) {
  let v;
  try {
    v = JSON.parse(lit);
  } catch {
    fail("corrupt");
  }
  if (typeof v !== "string" || !v.isWellFormed() || JSON.stringify(v) !== lit) fail("corrupt");
  return v;
}

/** Plaintext → { text, files } with every check of FORMAT.md 3 and 4. */
export function decodePlaintext(plain, version) {
  if (!BUCKETS.includes(plain.length)) fail("corrupt");
  const len = new DataView(plain.buffer, plain.byteOffset).getUint32(0);
  if (len > plain.length - 4) fail("corrupt");
  let s;
  try {
    s = strictUtf8.decode(plain.subarray(4, 4 + len));
  } catch {
    fail("corrupt");
  }
  let end = 4 + len;
  const take = (size) => {
    if (end + size > plain.length) fail("corrupt");
    const data = plain.slice(end, end + size);
    end += size;
    return data;
  };
  let text = "";
  const files = [];
  if (version === 2) {
    let v;
    try {
      v = JSON.parse(s);
    } catch {
      fail("corrupt");
    }
    const ok =
      v !== null &&
      typeof v === "object" &&
      typeof v.text === "string" &&
      v.text.isWellFormed() &&
      Array.isArray(v.files) &&
      v.files.length >= 1 &&
      v.files.length <= MAX_FILES &&
      !(v.files.length === 1 && v.text === "") &&
      v.files.every(
        (f) =>
          f !== null &&
          typeof f === "object" &&
          validName(f.name) &&
          Number.isSafeInteger(f.size) &&
          f.size >= 1,
      );
    if (!ok) fail("corrupt");
    // Accepted only if the canonical rewrite gives the same bytes (order, spaces, extra fields).
    const list = v.files.map((f) => `{"name":${JSON.stringify(f.name)},"size":${f.size}}`);
    if (s !== `{"kind":"bundle","text":${JSON.stringify(v.text)},"files":[${list.join(",")}]}`) {
      fail("corrupt");
    }
    text = v.text;
    for (const f of v.files) files.push({ name: f.name, data: take(f.size) });
  } else if (version === 1 && s.startsWith('{"kind":"text","text":') && s.endsWith("}")) {
    text = canonicalString(s.slice('{"kind":"text","text":'.length, -1));
    if (text === "") fail("corrupt");
  } else if (version === 1 && s.startsWith('{"kind":"file","name":') && s.endsWith("}")) {
    const rest = s.slice('{"kind":"file","name":'.length, -1);
    const at = rest.lastIndexOf(',"size":');
    if (at < 0) fail("corrupt");
    const digits = rest.slice(at + ',"size":'.length);
    if (!/^[1-9][0-9]{0,7}$/.test(digits)) fail("corrupt");
    const name = canonicalString(rest.slice(0, at));
    if (!validName(name)) fail("corrupt");
    files.push({ name, data: take(Number(digits)) });
  } else {
    fail("corrupt");
  }
  if (plain.subarray(end).some((b) => b !== 0)) fail("corrupt");
  // Only the smallest bucket that fits: the same content in a larger bucket is another record.
  if (BUCKETS.find((b) => b >= end) !== plain.length) fail("corrupt");
  return { text, files };
}

/** K_enc (FORMAT.md 1). */
async function deriveKey(kUrl, salt, passphrase) {
  let ikm = kUrl;
  if (passphrase !== null) {
    if (passphrase === "") fail("empty_passphrase");
    if (!passphrase.isWellFormed()) fail("bad_passphrase");
    const pw = await subtle.importKey(
      "raw",
      utf8.encode(passphrase.normalize("NFC")),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const p = new Uint8Array(
      await subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
        pw,
        256,
      ),
    );
    ikm = new Uint8Array([...kUrl, ...p]);
  }
  const base = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: HKDF_INFO },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Seal a plaintext with given random values (tests) → envelope (FORMAT.md 2). */
export async function seal(plain, version, kUrl, salt, iv, passphrase) {
  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC, 0);
  header[4] = version;
  header[5] = passphrase === null ? 0 : FLAG_PASSPHRASE;
  header.set(salt, 6);
  header.set(iv, 22);
  const key = await deriveKey(kUrl, salt, passphrase);
  const ct = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv, additionalData: header }, key, plain),
  );
  const env = new Uint8Array(HEADER_LEN + ct.length);
  env.set(header, 0);
  env.set(ct, HEADER_LEN);
  return env;
}

/** Encrypt text and files with fresh random values → { envelope, kUrl }. */
export async function encrypt(text, files, passphrase, maxBucket) {
  const { plain, version } = encodePlaintext(text, files, maxBucket);
  const kUrl = random(32);
  const envelope = await seal(plain, version, kUrl, random(16), random(12), passphrase);
  return { envelope, kUrl };
}

/** Does the envelope need a passphrase? Header checks only, no key. */
export function needsPassphrase(env) {
  const okHeader =
    ENVELOPE_LENGTHS.includes(env.length) &&
    MAGIC.every((b, i) => env[i] === b) &&
    (env[4] === 1 || env[4] === 2) &&
    (env[5] & ~FLAG_PASSPHRASE) === 0;
  if (!okHeader) fail("corrupt");
  return (env[5] & FLAG_PASSPHRASE) !== 0;
}

/** Envelope → { text, files }; the order of checks decides the error (FORMAT.md 3). */
export async function decrypt(env, kUrl, passphrase) {
  const flagged = needsPassphrase(env);
  if (flagged && passphrase === null) fail("need_passphrase");
  const header = env.subarray(0, HEADER_LEN);
  let plain;
  try {
    const key = await deriveKey(kUrl, env.subarray(6, 22), flagged ? passphrase : null);
    plain = new Uint8Array(
      await subtle.decrypt(
        { name: "AES-GCM", iv: env.subarray(22, 34), additionalData: header },
        key,
        env.subarray(HEADER_LEN),
      ),
    );
  } catch (e) {
    if (e instanceof FormatError && e.code !== "corrupt") throw e;
    fail("decrypt_failed");
  }
  return decodePlaintext(plain, env[4]);
}

// ---------- HTTP API (FORMAT.md 6) ----------

const MAX_RESPONSE = HEADER_LEN + 1048576 + TAG_LEN;

export class Client {
  /** `origin`: https://host[:port], no path; every request goes only there. Plain http only for
   * a test server on this machine (127.0.0.1 or localhost with a port). */
  constructor(origin, { accessToken = null } = {}) {
    const https = /^https:\/\/[a-z0-9.-]+(:\d{1,5})?$/.test(origin);
    const loopback = /^http:\/\/(127\.0\.0\.1|localhost):\d{1,5}$/.test(origin);
    if (!https && !loopback) throw new Error("bad origin");
    this.origin = origin;
    this.accessToken = accessToken;
  }

  async call(method, path, { body, headers = {} } = {}) {
    const h = { "X-Secret-Drop": "1", ...headers };
    if (this.accessToken) h["cf-access-token"] = this.accessToken;
    // A redirect is Cloudflare Access asking for login: the request never reached the service.
    const r = await fetch(this.origin + path, { method, headers: h, body, redirect: "manual" });
    if (r.status >= 300 && r.status < 400) {
      throw new Error("login required: set SDROP_ACCESS_TOKEN (cloudflared access token)");
    }
    const bytes = new Uint8Array(await r.arrayBuffer());
    if (bytes.length > MAX_RESPONSE) throw new Error("response too large");
    return { status: r.status, bytes, json: () => JSON.parse(new TextDecoder().decode(bytes)) };
  }

  async limit() {
    const r = await this.call("GET", "/api/limits");
    const n = r.status === 200 ? r.json().maxBucket : null;
    if (!BUCKETS.includes(n)) throw new Error(`limits: unexpected answer (HTTP ${r.status})`);
    return n;
  }

  /** → { recipient, owner, expiresAt }; the recipient link carries the key, never sent here. */
  async create(text, files, passphrase, ttl = 86400) {
    if (!TTLS.includes(ttl)) throw new Error("ttl: 3600, 86400 or 604800");
    const { envelope, kUrl } = await encrypt(text, files, passphrase, await this.limit());
    const r = await this.call("POST", `/api/secrets?ttl=${ttl}`, {
      body: envelope,
      headers: { "Content-Type": "application/octet-stream" },
    });
    if (r.status === 413) throw new Error("larger than the service limit");
    if (r.status === 429) throw new Error("too many secrets created, wait a minute");
    if (r.status !== 201) throw new Error(`create: HTTP ${r.status}`);
    const { id, ownerToken, expiresAt } = r.json();
    if (!/^[0-9a-f]{64}$/.test(id)) throw new Error("create: unexpected answer");
    decodeKey(ownerToken);
    return {
      recipient: `${this.origin}/s/${id}#${b64url(kUrl)}${passphrase === null ? "" : "~p"}`,
      owner: `${this.origin}/o/${id}#${ownerToken}`,
      expiresAt,
    };
  }

  /** The envelope, once: the server deletes it in the same request. null: not available. */
  async consume(id) {
    const r = await this.call("POST", `/api/secrets/${id}/consume`);
    if (r.status === 404) return null;
    if (r.status !== 200) throw new Error(`consume: HTTP ${r.status}`);
    return r.bytes;
  }

  async status(id, ownerToken) {
    const r = await this.call("GET", `/api/secrets/${id}/status`, {
      headers: { Authorization: `Bearer ${ownerToken}` },
    });
    if (r.status === 404) return null;
    if (r.status !== 200) throw new Error(`status: HTTP ${r.status}`);
    return r.json();
  }

  /** "revoked", "already_read" (with the status) or null (not found). */
  async revoke(id, ownerToken) {
    const r = await this.call("DELETE", `/api/secrets/${id}`, {
      headers: { Authorization: `Bearer ${ownerToken}` },
    });
    if (r.status === 204) return { result: "revoked" };
    if (r.status === 409) return { result: "already_read", status: r.json() };
    if (r.status === 404) return null;
    throw new Error(`revoke: HTTP ${r.status}`);
  }
}

// ---------- Self-test against spec/ (FORMAT.md 7) ----------

const hex = (s) => new Uint8Array(Buffer.from(s, "hex"));
const toHex = (b) => Buffer.from(b).toString("hex");
const sha256 = async (b) => new Uint8Array(await subtle.digest("SHA-256", b));

/** File bytes: hex, or SHA-256(seed + "/" + offset) blocks cut to `size` (compact vectors). */
async function vectorData(f) {
  if (f.data_hex !== undefined) return hex(f.data_hex);
  const out = new Uint8Array(f.size);
  for (let off = 0; off < f.size; off += 32) {
    const block = await sha256(utf8.encode(`${f.data_seed}/${off}`));
    out.set(block.subarray(0, Math.min(32, f.size - off)), off);
  }
  return out;
}

async function selftest(dir) {
  const load = (n) => JSON.parse(readFileSync(join(dir, n), "utf8"));
  let checked = 0;
  for (const v of load("vectors.json")) {
    let text = "";
    let files = [];
    if (v.text !== undefined) text = v.text;
    if (v.text_repeat) text = v.text_repeat.char.repeat(v.text_repeat.count);
    if (v.file) files = [{ name: v.file.name, data: await vectorData(v.file) }];
    if (v.bundle) {
      text = v.bundle.text;
      files = await Promise.all(
        v.bundle.files.map(async (f) => ({ name: f.name, data: await vectorData(f) })),
      );
    }
    const { plain, version } = encodePlaintext(text, files);
    if (plain.length !== v.bucket) throw new Error(`${v.name}: bucket ${plain.length}`);
    const kUrl = decodeKey(v.k_url);
    const env = await seal(plain, version, kUrl, hex(v.salt), hex(v.iv), v.passphrase);
    const same = v.envelope_hex
      ? toHex(env) === v.envelope_hex
      : toHex(await sha256(env)) === v.envelope_sha256;
    if (!same) throw new Error(`${v.name}: envelope differs`);
    const got = await decrypt(env, kUrl, v.passphrase);
    const sameSecret =
      got.text === text &&
      got.files.length === files.length &&
      got.files.every((f, i) => f.name === files[i].name && toHex(f.data) === toHex(files[i].data));
    if (!sameSecret) throw new Error(`${v.name}: decrypted secret differs`);
    checked++;
  }
  for (const v of load("vectors-invalid.json")) {
    let code = "accepted";
    try {
      await decrypt(hex(v.envelope_hex), decodeKey(v.k_url), v.passphrase);
    } catch (e) {
      code = e instanceof FormatError ? e.code : String(e);
    }
    if (code !== v.error) throw new Error(`${v.name}: ${code}, expected ${v.error}`);
    checked++;
  }
  const links = load("links.json");
  for (const l of links.valid) {
    const p = parseRecipientFragment(l.fragment);
    if (toHex(p.key) !== l.key_hex || p.passphraseHint !== l.passphrase_hint) {
      throw new Error(`link ${l.fragment}: differs`);
    }
    checked++;
  }
  for (const l of links.invalid) {
    let accepted = true;
    try {
      parseRecipientFragment(l.fragment);
    } catch {
      accepted = false;
    }
    if (accepted) throw new Error(`link ${l.name}: accepted`);
    checked++;
  }
  console.log(`selftest: ${checked} vectors passed`);
}

// ---------- Command line ----------

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks);
}

/** The controlling terminal, apart from stdin (which may carry the link): null if there is none. */
function openTerminal() {
  for (const [input, output] of [
    ["/dev/tty", "/dev/tty"],
    ["CONIN$", "CONOUT$"],
  ]) {
    try {
      const i = openSync(input, "r");
      const o = openSync(output, "w");
      return { input: new tty.ReadStream(i), output: new tty.WriteStream(o), fds: [i, o] };
    } catch {
      // not this platform
    }
  }
  return null;
}

/** A line typed on the terminal without echo (passphrases) or with echo; null without a terminal. */
export async function askTerminal(prompt, { echo }) {
  const t = openTerminal();
  if (!t) return null;
  // Echo is off before the prompt appears, so nothing typed after it is shown.
  t.input.setRawMode(true);
  t.output.write(prompt);
  let line = "";
  // A character may arrive split across reads (SSH, slow terminals): decode as a stream.
  const utf8Stream = new StringDecoder("utf8");
  try {
    return await new Promise((resolve, reject) => {
      t.input.on("data", (buf) => {
        for (const ch of utf8Stream.write(buf)) {
          if (ch === "\r" || ch === "\n") return resolve(line);
          if (ch === "\u0003") return reject(new Error("interrupted"));
          if (ch === "\u007f" || ch === "\b") {
            line = [...line].slice(0, -1).join("");
            if (echo) t.output.write("\b \b");
          } else if (ch >= " ") {
            line += ch;
            if (echo) t.output.write(ch);
          }
        }
      });
    });
  } finally {
    t.output.write("\n");
    t.input.setRawMode(false);
    t.input.destroy();
    t.output.destroy();
  }
}

/** Asked on the terminal without echo; an empty answer is asked again (a stray Enter must not
 * cost the secret). null without a terminal. */
export async function askPassphrase(prompt) {
  for (;;) {
    const p = await askTerminal(prompt, { echo: false });
    if (p === null || p !== "") return p;
  }
}

/** Text to stdout and files into a new private directory; on any failure everything stays in
 * memory and another directory is asked for (the server copy is already gone). */
/** Write to stdout and wait for the result (a closed pipe or a full disk is an error, not a
 * crash). The error event may come after the write callback: a handler stays for good. */
let stdoutError = null;
function writeStdout(data) {
  if (process.stdout.listenerCount("error") === 0) {
    process.stdout.on("error", (e) => {
      stdoutError ??= e;
    });
  }
  return new Promise((resolve) => {
    process.stdout.write(data, (e) => resolve(e ?? stdoutError));
  });
}

async function deliver(secret, id) {
  // The text to stdout; if that fails, it is saved with the files instead.
  const entries = secret.files.map((f, i) => ({ path: `file-${i + 1}`, data: f.data, name: f.name }));
  if (secret.text) {
    const e = await writeStdout(secret.text + "\n");
    if (e) {
      console.error(`Cannot write the text to stdout (${e.code ?? e.message}); saving it as a file.`);
      entries.unshift({ path: "text", data: utf8.encode(secret.text), name: null });
    }
  }
  if (entries.length === 0) return;
  let dir = `sdrop-${id.slice(0, 8)}`;
  let triedTemp = false;
  for (;;) {
    try {
      mkdirSync(dir, { mode: 0o700 }); // fails if it exists: never write into someone's directory
      try {
        // Sender names are only shown, never used as paths.
        for (const e of entries) {
          writeFileSync(join(dir, e.path), e.data, { mode: 0o600, flag: "wx" });
        }
      } catch (e) {
        rmSync(dir, { recursive: true, force: true }); // only what this call created
        throw e;
      }
      for (const e of entries) {
        const named = e.name === null ? "the text" : `the sender named it ${JSON.stringify(e.name)}`;
        console.error(`${dir}/${e.path}: ${named}`);
      }
      return;
    } catch (e) {
      console.error(`Cannot save into ${dir}: ${e.code ?? e.message}. The secret is kept in memory.`);
      const typed = await askTerminal("Save into a new directory: ", { echo: true });
      // An empty answer is asked again (the next failure asks once more); only without a terminal:
      // one last try in the system temporary directory.
      const fallback = join(tmpdir(), `sdrop-${id.slice(0, 8)}-${Date.now()}`);
      dir = typed === null ? (triedTemp ? null : fallback) : typed.trim() || dir;
      triedTemp ||= typed === null;
      if (!dir) throw new Error("could not save the files; the secret is already deleted from the server");
    }
  }
}

function client() {
  const origin = process.env.SDROP_ORIGIN;
  if (!origin) throw new Error("set SDROP_ORIGIN, e.g. https://secrets.example.com");
  return new Client(origin, { accessToken: process.env.SDROP_ACCESS_TOKEN || null });
}

async function main([cmd, ...args]) {
  if (cmd === "selftest") {
    return selftest(args[0] ?? new URL("../../spec/", import.meta.url).pathname);
  }
  if (cmd === "put") {
    let ttl = 86400;
    if (args[0] === "--ttl") {
      ttl = Number(args[1]);
      args = args.slice(2);
    }
    const files = args.map((p) => ({ name: sanitizeName(basename(p)), data: readFileSync(p) }));
    const text = process.stdin.isTTY ? "" : strictUtf8.decode(await readStdin()).replace(/\n$/, "");
    const c = await client().create(text, files, process.env.SDROP_PASSPHRASE || null, ttl);
    console.log(c.recipient); // for the recipient
    console.error(`Only for you, to check or revoke: ${c.owner}\nExpires: ${c.expiresAt}`);
    return;
  }
  if (args.length > 0) throw new Error("pass the link on stdin, not as an argument");
  if (cmd === "get") {
    const c = client();
    // The whole link is checked before any request: a broken link consumes nothing.
    const link = parseLink((await readStdin()).toString("utf8"), c.origin, "s");
    // A passphrase given in the environment is used whether or not the link says `~p`.
    let pass = process.env.SDROP_PASSPHRASE || null;
    if (link.passphraseHint && pass === null) {
      pass = await askPassphrase("Passphrase: ");
      if (pass === null) throw new Error("the link needs a passphrase: set SDROP_PASSPHRASE");
    }
    const env = await c.consume(link.id);
    if (env === null) {
      throw new Error("not found, already read, revoked or expired; if not by you, tell the sender");
    }
    // From here the server copy is gone: wrong passphrases are retried with this envelope.
    let secret;
    for (let attempt = 0; ; attempt++) {
      try {
        secret = await decrypt(env, link.key, pass);
        break;
      } catch (e) {
        const retry = e.code === "need_passphrase" || (e.code === "decrypt_failed" && pass !== null);
        if (!retry || attempt >= 3) throw e;
        pass = await askPassphrase("Passphrase (the secret is already deleted from the server): ");
        if (pass === null) {
          throw new Error("no terminal to ask the passphrase; the secret is already deleted from the server");
        }
      }
    }
    return deliver(secret, link.id);
  }
  if (cmd === "status" || cmd === "revoke") {
    const c = client();
    const link = parseLink((await readStdin()).toString("utf8"), c.origin, "o");
    const r =
      cmd === "status"
        ? await c.status(link.id, link.ownerToken)
        : await c.revoke(link.id, link.ownerToken);
    console.log(r === null ? "not found or expired" : JSON.stringify(r));
    return;
  }
  console.error("usage: selftest | put [--ttl N] [file...] | get | status | revoke (links on stdin)");
  process.exitCode = 2;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).catch((e) => {
    console.error(`error: ${e instanceof FormatError ? `damaged or invalid (${e.code})` : e.message}`);
    process.exitCode = 1;
  });
}
