//! Secure Net's maintenance tools.
//!
//! ```text
//! cargo run -p secure-net-tools -- manifest            write secure-net.manifest.json
//! cargo run -p secure-net-tools -- manifest --check    fail if it's out of date
//! cargo run -p secure-net-tools -- standards           check the standard and the code agree
//! cargo run -p secure-net-tools -- standards --write   also regenerate spec/REGISTRIES.md and the spec index
//! cargo run -p secure-net-tools -- package             build the npm package (pkg/web and pkg/node)
//! ```
//!
//! The vectors in `spec/vectors` are checked by `cargo test` (`secure-net-core/tests/vectors*.rs`).
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repository root")
}

fn read(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |f: &str| args.iter().any(|a| a == f);
    match args.first().map(String::as_str) {
        Some("manifest") => manifest::run(flag("--check")),
        Some("standards") => standards::run(flag("--write")),
        Some("package") => package::run(),
        _ => {
            eprintln!("usage: secure-net-tools manifest [--check] | standards [--write] | package");
            ExitCode::from(2)
        }
    }
}

/// JSON with two-space indents, as `JSON.stringify(v, null, 2)` writes it.
fn pretty(v: &Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(v).expect("JSON"))
}

mod manifest {
    //! `secure-net.manifest.json`: the version and a SHA-256 of every file an app copies in. Apps
    //! that keep a copy check it against this, so a copy can't drift from a release unnoticed.
    use super::*;

    /// What an app copies in: the Rust crates (with the patched OpenMLS), the standard and the package.
    pub const INCLUDE: [&str; 13] = ["package.json", "README.md", "LICENSE", "GOVERNANCE.md", "snips", "spec", "secure-net-conformance.json", "rust/Cargo.toml", "rust/Cargo.lock", "rust/README.md", "rust/secure-net-core", "rust/secure-net-wasm", "rust/vendor"];

    pub fn files_of(dir: &Path) -> Vec<String> {
        fn walk(dir: &Path, rel: &str, out: &mut Vec<String>) {
            let abs = dir.join(rel);
            if abs.is_dir() {
                let mut names: Vec<String> = fs::read_dir(&abs).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
                names.sort();
                for n in names {
                    walk(dir, &format!("{rel}/{n}"), out);
                }
            } else if abs.exists() {
                out.push(rel.to_string());
            }
        }
        let mut out = Vec::new();
        for p in INCLUDE {
            walk(dir, p, &mut out);
        }
        out
    }

    pub fn manifest_of(dir: &Path) -> Value {
        let pkg: Value = serde_json::from_str(&read(&dir.join("package.json"))).unwrap();
        let mut files = Map::new();
        for f in files_of(dir) {
            let digest = Sha256::digest(fs::read(dir.join(&f)).unwrap());
            files.insert(f, json!(URL_SAFE_NO_PAD.encode(digest)));
        }
        json!({ "name": "secure-net", "version": pkg["version"], "files": files })
    }

    pub fn run(check: bool) -> ExitCode {
        let dir = root();
        let file = dir.join("secure-net.manifest.json");
        let want = pretty(&manifest_of(&dir));
        if check {
            if fs::read_to_string(&file).ok().as_deref() != Some(want.as_str()) {
                eprintln!("secure-net.manifest.json is out of date: run cargo run -p secure-net-tools -- manifest");
                return ExitCode::FAILURE;
            }
            println!("Manifest is up to date.");
        } else {
            fs::write(&file, &want).unwrap();
            let n = serde_json::from_str::<Value>(&want).unwrap()["files"].as_object().unwrap().len();
            println!("Wrote secure-net.manifest.json ({n} files).");
        }
        ExitCode::SUCCESS
    }
}

mod package {
    //! The npm package is the WebAssembly build: `pkg/web` (an ES module; call `init()` first) and
    //! `pkg/node` (CommonJS, ready on import). Needs the wasm32 target and `wasm-bindgen` (the CLI
    //! of the same version as the `wasm-bindgen` crate in Cargo.lock).
    use super::*;
    use std::process::Command;

    fn sh(cmd: &mut Command) -> bool {
        let ok = cmd.status().map(|s| s.success()).unwrap_or(false);
        if !ok {
            eprintln!("failed: {cmd:?}");
        }
        ok
    }

    pub fn run() -> ExitCode {
        let root = root();
        let rust = root.join("rust");
        if !sh(Command::new("cargo").current_dir(&rust).args(["build", "--locked", "--release", "--target", "wasm32-unknown-unknown", "-p", "secure-net-wasm"])) {
            return ExitCode::FAILURE;
        }
        let wasm = rust.join("target/wasm32-unknown-unknown/release/secure_net_wasm.wasm");
        for (target, dir) in [("web", "pkg/web"), ("nodejs", "pkg/node")] {
            let out = root.join(dir);
            let _ = fs::remove_dir_all(&out);
            if !sh(Command::new("wasm-bindgen").args(["--target", target, "--out-dir"]).arg(&out).arg(&wasm)) {
                return ExitCode::FAILURE;
            }
            let _ = fs::remove_file(out.join(".gitignore"));
        }
        // wasm-bindgen's Node.js output is CommonJS; the package says ES modules.
        fs::write(root.join("pkg/node/package.json"), "{ \"type\": \"commonjs\" }\n").unwrap();
        println!("Built pkg/web and pkg/node.");
        ExitCode::SUCCESS
    }
}

mod scan {
    //! Reading names out of the Rust source.
    use super::*;

    pub fn rust_files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let mut entries: Vec<PathBuf> = fs::read_dir(&d).unwrap().map(|e| e.unwrap().path()).collect();
            entries.sort();
            for p in entries {
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|e| e == "rs") {
                    out.push(p);
                }
            }
        }
        out.sort();
        out
    }

    /// Every double-quoted string literal in Rust source (comments, chars and lifetimes skipped),
    /// with escapes left as written.
    pub fn strings(src: &str) -> Vec<String> {
        let b = src.as_bytes();
        let (mut i, mut out) = (0, Vec::new());
        while i < b.len() {
            match b[i] {
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                }
                b'/' if b.get(i + 1) == Some(&b'*') => {
                    i += 2;
                    while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                        i += 1;
                    }
                    i += 2;
                }
                b'\'' => {
                    if b.get(i + 1) == Some(&b'\\') {
                        i += 2;
                        while i < b.len() && b[i] != b'\'' {
                            i += 1;
                        }
                        i += 1;
                    } else if b.get(i + 2) == Some(&b'\'') {
                        i += 3;
                    } else {
                        i += 1;
                    }
                }
                b'r' if b.get(i + 1) == Some(&b'#') || (b.get(i + 1) == Some(&b'"') && (i == 0 || !b[i - 1].is_ascii_alphanumeric() && b[i - 1] != b'_')) => {
                    let mut j = i + 1;
                    let mut hashes = 0;
                    while b.get(j) == Some(&b'#') {
                        hashes += 1;
                        j += 1;
                    }
                    if b.get(j) != Some(&b'"') {
                        i += 1;
                        continue;
                    }
                    let start = j + 1;
                    let close: Vec<u8> = std::iter::once(b'"').chain(std::iter::repeat_n(b'#', hashes)).collect();
                    let mut k = start;
                    while k + close.len() <= b.len() && b[k..k + close.len()] != close[..] {
                        k += 1;
                    }
                    out.push(src[start..k].to_string());
                    i = k + close.len();
                }
                b'"' => {
                    let start = i + 1;
                    let mut k = start;
                    while k < b.len() && b[k] != b'"' {
                        k += if b[k] == b'\\' { 2 } else { 1 };
                    }
                    out.push(src[start..k.min(b.len())].to_string());
                    i = k + 1;
                }
                _ => i += 1,
            }
        }
        out
    }

    /// `pub const NAME: &str = "value";` and `pub const NAME: [&str; N] = ["a", "b"];` in a file.
    pub fn consts(src: &str) -> BTreeMap<String, Vec<String>> {
        let mut out = BTreeMap::new();
        for chunk in src.split("pub const ").skip(1) {
            let Some((name, rest)) = chunk.split_once(':') else { continue };
            let Some(eq) = rest.find('=') else { continue };
            let ty = rest[..eq].trim();
            let Some(end) = rest[eq..].find(';') else { continue };
            let value = &rest[eq + 1..eq + end];
            if ty == "&str" || (ty.starts_with("[&str;") && ty.ends_with(']')) {
                out.insert(name.trim().to_string(), strings(value));
            }
        }
        out
    }
}

mod standards {
    //! Keeps the standard and the code in step (CVP-000, sections 3 and 7): the registries are
    //! well formed, every name the code uses is registered and every registered name is really
    //! there, part documents carry what CVP-000 requires, and generated documents are current.
    use super::*;
    use secure_net_core::{commons, consent, extensions, governance::vote, session::primitives as sp, social, wire};

    fn is_kind(s: &str) -> bool {
        let mut parts = s.split('.');
        let ok = |p: &str| p.as_bytes().first().is_some_and(u8::is_ascii_lowercase) && p.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        s.contains('.') && parts.all(ok)
    }
    fn is_part_id(s: &str) -> bool {
        s.len() == 7 && s.starts_with("CVP-") && s[4..].bytes().all(|c| c.is_ascii_digit())
    }
    fn is_feature(s: &str) -> bool {
        s.strip_prefix("cvp.").is_some_and(|r| r.as_bytes().first().is_some_and(u8::is_ascii_lowercase) && r.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'))
    }
    fn placeholders(s: &str) -> String {
        let mut out = String::new();
        let mut inside = false;
        for c in s.chars() {
            match (c, inside) {
                ('<', false) => {
                    inside = true;
                    out.push_str("<>");
                }
                ('>', true) => inside = false,
                (_, true) => {}
                (c, false) => out.push(c),
            }
        }
        out
    }
    fn names(list: &Value, key: &str) -> Vec<String> {
        list.as_array().into_iter().flatten().map(|e| e[key].as_str().unwrap_or("").to_string()).collect()
    }
    fn same_set<A: AsRef<str>, B: AsRef<str>>(a: &[A], b: &[B]) -> bool {
        let x: BTreeSet<&str> = a.iter().map(AsRef::as_ref).collect();
        let y: BTreeSet<&str> = b.iter().map(AsRef::as_ref).collect();
        a.len() == b.len() && x == y
    }
    fn diff<'a>(a: &'a [String], b: &[String]) -> Vec<&'a String> {
        let mut seen = BTreeSet::new();
        a.iter().filter(|x| !b.contains(x) && seen.insert(x.as_str())).collect()
    }
    fn live(list: &Value) -> impl Iterator<Item = &Value> {
        list.as_array().into_iter().flatten().filter(|e| e["status"] != "removed")
    }

    struct Doc {
        status: Option<String>,
        version: Option<String>,
        headings: Vec<String>,
    }
    fn doc_header(text: &str) -> Doc {
        let row = |name: &str| {
            text.lines().find_map(|l| {
                let cells: Vec<&str> = l.split('|').collect();
                (cells.len() >= 3 && cells[0].trim().is_empty() && cells[1].trim() == name).then(|| cells[2].trim().to_string())
            })
        };
        let headings = text.lines().filter_map(|l| l.strip_prefix("### ").or_else(|| l.strip_prefix("## "))).map(str::to_lowercase).collect();
        Doc { status: row("Status"), version: row("Version"), headings }
    }

    /// Labels written in the code: string literals starting `secure-net` or `commonveil`.
    fn labels_in_code(src_dir: &Path) -> BTreeMap<String, String> {
        let mut found = BTreeMap::new();
        for file in scan::rust_files(src_dir) {
            let full = read(&file);
            let text = full.split("#[cfg(test)]").next().unwrap().replace("{LABEL}", sp::LABEL);
            let rel = file.strip_prefix(root()).unwrap().display().to_string();
            for s in scan::strings(&text) {
                if !(s.starts_with("secure-net") || s.starts_with("commonveil")) {
                    continue;
                }
                let mut v = String::new();
                let mut depth = 0;
                for c in s.chars() {
                    match c {
                        '{' => {
                            if depth == 0 {
                                v.push_str("<x>");
                            }
                            depth += 1;
                        }
                        '}' => depth -= 1,
                        _ if depth > 0 => {}
                        c => v.push(c),
                    }
                }
                let cut = v.split("\\n").next().unwrap().split(['\n', '|']).next().unwrap().to_string();
                found.entry(cut).or_insert_with(|| rel.clone());
            }
        }
        found
    }

    pub struct Outcome {
        pub problems: Vec<String>,
        pub warnings: Vec<String>,
    }

    pub fn check() -> Outcome {
        let root = root();
        let spec = |f: &str| root.join("spec").join(f);
        let mut problems: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let reg: Value = serde_json::from_str(&read(&spec("registry.json"))).unwrap();
        let mut bad = |m: String| problems.push(m);

        // ---- The registries themselves ----
        let parts: BTreeMap<String, &Value> = reg["parts"].as_array().unwrap().iter().map(|p| (p["id"].as_str().unwrap().to_string(), p)).collect();
        let unique = |list: &Value, key: &str, what: &str, bad: &mut dyn FnMut(String)| {
            let mut seen = BTreeSet::new();
            for n in names(list, key) {
                if !seen.insert(n.clone()) {
                    bad(format!("{what} \"{n}\" is registered twice"));
                }
            }
        };
        unique(&reg["parts"], "id", "Part", &mut bad);
        let statuses = names_of(&reg["entryStatuses"]);
        for (name, key) in [("features", "name"), ("recordKinds", "name"), ("ledgerEvents", "name"), ("capabilities", "name"), ("extensionExecution", "name"), ("consentActions", "name"), ("voteMethods", "name"), ("suites", "name"), ("labels", "label"), ("identifiers", "name"), ("endpoints", "name"), ("headers", "name"), ("profiles", "name"), ("actorTypes", "name"), ("activityTypes", "name"), ("objectTypes", "name"), ("addresses", "name"), ("envelopeModes", "name"), ("lexiconFieldTypes", "name")] {
            unique(&reg[name], key, name, &mut bad);
            for e in reg[name].as_array().unwrap() {
                if let Some(p) = e["part"].as_str() {
                    if !parts.contains_key(p) {
                        bad(format!("{name} \"{}\" names unknown part {p}", e[key].as_str().unwrap_or("")));
                    }
                }
                if let Some(s) = e["status"].as_str() {
                    if !statuses.iter().any(|x| x == s) {
                        bad(format!("{name} \"{}\" has unknown status \"{s}\"", e[key].as_str().unwrap_or("")));
                    }
                }
            }
        }
        let part_statuses = names_of(&reg["partStatuses"]);
        for p in reg["parts"].as_array().unwrap() {
            let id = p["id"].as_str().unwrap();
            let status = p["status"].as_str().unwrap_or("");
            if !is_part_id(id) {
                bad(format!("\"{id}\" isn't a part id"));
            }
            if !part_statuses.iter().any(|x| x == status) {
                bad(format!("{id} has unknown status \"{status}\""));
            }
            let min = if status == "Reserved" { 0 } else { 1 };
            if !p["version"].as_i64().is_some_and(|v| v >= min) {
                bad(format!("{id} has a bad version"));
            }
            for d in names_of(&p["dependsOn"]) {
                if !parts.contains_key(&d) {
                    bad(format!("{id} depends on unknown part {d}"));
                }
            }
            for v in names_of(&p["vectors"]) {
                if !spec(&v).exists() {
                    bad(format!("{id}: vectors {v} don't exist"));
                }
            }
            for f in names_of(&p["features"]) {
                if !reg["features"].as_array().unwrap().iter().any(|x| x["name"] == f.as_str() && x["part"] == id) {
                    bad(format!("{id} lists feature {f}, but the feature doesn't name it"));
                }
            }
            if status != "Reserved" && p["doc"].as_str().is_none() {
                warnings.push(format!("{id} ({}) has no part document yet", p["title"].as_str().unwrap_or("")));
            }
            if let Some(doc) = p["doc"].as_str() {
                if !spec(doc).exists() {
                    bad(format!("{id}: {doc} doesn't exist"));
                    continue;
                }
                let h = doc_header(&read(&spec(doc)));
                if !h.status.as_deref().is_some_and(|s| s.starts_with(status)) {
                    bad(format!("{doc}: Status should start \"{status}\" (the registry), not \"{}\"", h.status.as_deref().unwrap_or("missing")));
                }
                if h.version.as_deref() != Some(p["version"].to_string().as_str()) {
                    bad(format!("{doc}: Version should be {} (the registry), not \"{}\"", p["version"], h.version.as_deref().unwrap_or("missing")));
                }
                let has = |f: &dyn Fn(&str) -> bool| h.headings.iter().any(|x| f(x));
                if !has(&|x| x.contains("secur") || x.contains("protect")) {
                    bad(format!("{doc} has no security and privacy section (CVP-000, 3.1)"));
                }
                if !has(&|x| x.contains("conformance")) {
                    bad(format!("{doc} has no conformance section (CVP-000, 3.1)"));
                }
                if !has(&|x| x == "changes") {
                    bad(format!("{doc} has no changes section (CVP-000, 3.1)"));
                }
            }
        }
        for f in reg["features"].as_array().unwrap() {
            let (n, part) = (f["name"].as_str().unwrap_or(""), f["part"].as_str().unwrap_or(""));
            if !is_feature(n) {
                bad(format!("Feature \"{n}\" doesn't follow cvp.<name>"));
            }
            if !parts.get(part).is_some_and(|p| names_of(&p["features"]).iter().any(|x| x == n)) {
                bad(format!("Feature {n} names {part}, but that part doesn't list it"));
            }
        }
        for k in reg["recordKinds"].as_array().unwrap().iter().chain(reg["ledgerEvents"].as_array().unwrap()) {
            let n = k["name"].as_str().unwrap_or("");
            if !is_kind(n) && k.get("grandfathered").is_none() {
                bad(format!("\"{n}\" doesn't follow <area>.<name>"));
            }
        }
        for l in names(&reg["labels"], "label") {
            if !l.starts_with("secure-net/") && !l.starts_with("commonveil") {
                bad(format!("Label \"{l}\" must start secure-net/"));
            }
        }
        for pr in reg["profiles"].as_array().unwrap() {
            for id in names_of(&pr["parts"]) {
                match parts.get(&id) {
                    None => bad(format!("Profile {} needs unknown part {id}", pr["name"].as_str().unwrap_or(""))),
                    Some(p) if p["status"] == "Reserved" => bad(format!("Profile {} needs {id}, which has no specification", pr["name"].as_str().unwrap_or(""))),
                    _ => {}
                }
            }
        }

        // ---- The registries against the code ----
        let pkg: Value = serde_json::from_str(&read(&root.join("package.json"))).unwrap();
        let version = pkg["version"].as_str().unwrap_or("");
        if reg["release"] != version {
            bad(format!("registry release {} isn't package.json's {version}", reg["release"].as_str().unwrap_or("")));
        }
        if wire::features::SECURE_NET_VERSION != version {
            bad(format!("SECURE_NET_VERSION {} isn't package.json's {version}", wire::features::SECURE_NET_VERSION));
        }
        let active: BTreeMap<String, i64> = live(&reg["features"]).map(|f| (f["name"].as_str().unwrap().to_string(), f["version"].as_i64().unwrap_or(0))).collect();
        for (n, v) in wire::features::FEATURES {
            if active.get(n) != Some(&v) {
                bad(format!("Feature {n} {v} in wire/features.rs isn't registered at that version"));
            }
        }
        for n in active.keys() {
            if !wire::features::FEATURES.iter().any(|(f, _)| f == n) {
                bad(format!("Feature {n} is registered but wire/features.rs doesn't announce it"));
            }
        }
        let identifiers = names(&reg["identifiers"], "name");
        let site = wire::features::describe_site(None);
        if site["protocol"] != "secure-net" || !identifiers.iter().any(|i| site["protocol"] == i.as_str()) {
            bad("The site document's protocol name isn't registered".into());
        }

        // Record kinds: string constants (and arrays of them) shaped like kinds, plus literals
        // passed straight to sign(). Commonveil's own cryptography (cv/) is outside the registry.
        let src = root.join("rust/secure-net-core/src");
        let mut kinds: Vec<String> = Vec::new();
        for file in scan::rust_files(&src).into_iter().filter(|f| !f.starts_with(src.join("cv"))) {
            let full = read(&file);
            let text = full.split("#[cfg(test)]").next().unwrap();
            for (_, values) in scan::consts(text) {
                if !values.is_empty() && values.iter().all(|v| is_kind(v)) {
                    kinds.extend(values);
                }
            }
            for chunk in text.split("sign(").skip(1) {
                if let Some(rest) = chunk.trim_start().strip_prefix('"') {
                    kinds.push(rest.split('"').next().unwrap().to_string());
                }
            }
        }
        kinds.sort();
        kinds.dedup();
        let reg_kinds: Vec<String> = live(&reg["recordKinds"]).map(|k| k["name"].as_str().unwrap().to_string()).collect();
        for k in diff(&kinds, &reg_kinds) {
            bad(format!("Record kind \"{k}\" is used in the code but not registered"));
        }
        for k in diff(&reg_kinds, &kinds) {
            bad(format!("Record kind \"{k}\" is registered but the code never defines it"));
        }

        let reg_events: BTreeMap<String, String> = live(&reg["ledgerEvents"]).map(|e| (e["name"].as_str().unwrap().to_string(), e["capability"].as_str().unwrap_or("").to_string())).collect();
        for (e, cap) in commons::EVENT_CAPS {
            if reg_events.get(e).map(String::as_str) != Some(cap) {
                bad(format!("Ledger event {e} (needs {cap}) isn't registered that way"));
            }
        }
        for e in reg_events.keys() {
            if !commons::EVENT_CAPS.iter().any(|(x, _)| x == e) {
                bad(format!("Ledger event {e} is registered but the ledger doesn't know it"));
            }
        }
        if !same_set(&commons::CAPS, &names(&reg["capabilities"], "name")) {
            bad(format!("Capabilities differ: code {}", commons::CAPS.join(", ")));
        }
        let reg_exec: BTreeMap<String, Vec<String>> = reg["extensionExecution"].as_array().unwrap().iter().map(|e| (e["name"].as_str().unwrap().to_string(), names_of(&e["permissions"]))).collect();
        if !same_set(&extensions::EXECUTION.iter().map(|(n, _)| *n).collect::<Vec<_>>(), &reg_exec.keys().cloned().collect::<Vec<_>>()) {
            bad("Extension execution models differ from the registry".into());
        }
        for (n, perms) in extensions::EXECUTION {
            if !reg_exec.get(n).is_some_and(|r| same_set(perms, r)) {
                bad(format!("Permissions for {n} extensions differ from the registry"));
            }
        }
        if !same_set(&consent::ACTIONS, &names(&reg["consentActions"], "name")) {
            bad("Consent actions differ from the registry".into());
        }
        if !same_set(&vote::METHODS, &names(&reg["voteMethods"], "name")) {
            bad("Vote methods differ from the registry".into());
        }
        let v = social::vocabulary::ACTOR_TYPES.to_vec();
        for (name, code, list) in [
            ("Actor types", v, "actorTypes"),
            ("Activity types", social::vocabulary::ACTIVITY_TYPES.to_vec(), "activityTypes"),
            ("Object types", social::vocabulary::OBJECT_TYPES.to_vec(), "objectTypes"),
            ("Addresses", vec![social::vocabulary::PUBLIC, social::vocabulary::FOLLOWERS], "addresses"),
            ("Envelope modes", social::delivery::MODES.to_vec(), "envelopeModes"),
            ("Lexicon field types", social::lexicon::FIELD_TYPES.to_vec(), "lexiconFieldTypes"),
        ] {
            let code: Vec<String> = code.into_iter().map(String::from).collect();
            let registered = names(&reg[list], "name");
            for n in diff(&code, &registered) {
                bad(format!("{name}: \"{n}\" is in the code but not registered"));
            }
            for n in diff(&registered, &code) {
                bad(format!("{name}: \"{n}\" is registered but not in the code"));
            }
        }
        for s in reg["suites"].as_array().unwrap() {
            let (file, name) = s["code"].as_str().unwrap_or("").split_once(' ').unwrap_or(("", ""));
            let consts = scan::consts(&fs::read_to_string(root.join(file)).unwrap_or_default());
            let got = consts.get(name).and_then(|v| v.first()).cloned();
            if got.as_deref() != s["name"].as_str() {
                bad(format!("Suite {}: {file} {name} is \"{}\"", s["name"].as_str().unwrap_or(""), got.unwrap_or_default()));
            }
        }
        let fed = &wire::federation::PROTOCOL;
        if !identifiers.iter().any(|i| i == fed) {
            bad(format!("Protocol identifier {fed} isn't registered"));
        }
        let reg_paths: BTreeMap<String, String> = reg["endpoints"].as_array().unwrap().iter().map(|e| (e["name"].as_str().unwrap().to_string(), e["path"].as_str().unwrap_or("").to_string())).collect();
        if reg_paths.get("site-document").map(String::as_str) != Some(wire::federation::SITE_DOCUMENT) {
            bad("The site document path differs from the registry".into());
        }
        for (n, _) in wire::federation::SOCIAL_ENDPOINTS {
            if wire::federation::DEFAULT_ENDPOINTS.iter().any(|(d, _)| *d == n) {
                bad(format!("Endpoint {n} is in both endpoint lists"));
            }
        }
        let code_endpoints: Vec<(&str, &str)> = wire::federation::DEFAULT_ENDPOINTS.iter().chain(wire::federation::SOCIAL_ENDPOINTS.iter()).copied().collect();
        for (n, p) in &code_endpoints {
            if reg_paths.get(*n).map(String::as_str) != Some(*p) {
                bad(format!("Endpoint {n} ({p}) isn't registered at that path"));
            }
        }
        for n in reg_paths.keys() {
            if n != "site-document" && !code_endpoints.iter().any(|(c, _)| c == n) {
                bad(format!("Endpoint {n} is registered but the code doesn't define it"));
            }
        }

        // Labels: everything written in the code, and every purpose the session protocol derives under.
        let mut in_code = labels_in_code(&src);
        for p in sp::PURPOSES {
            in_code.insert(format!("{}/{p}", sp::LABEL), "rust/secure-net-core/src/session/primitives.rs".into());
        }
        let reg_labels: BTreeMap<String, String> = live(&reg["labels"]).map(|l| l["label"].as_str().unwrap().to_string()).map(|l| (placeholders(&l), l)).collect();
        for (l, file) in &in_code {
            if !identifiers.contains(l) && !reg_labels.contains_key(&placeholders(l)) {
                bad(format!("Label \"{l}\" in {file} isn't registered"));
            }
        }
        let code_labels: BTreeSet<String> = in_code.keys().map(|l| placeholders(l)).collect();
        for (norm, l) in &reg_labels {
            if !code_labels.contains(norm) {
                bad(format!("Label \"{l}\" is registered but the code never uses it"));
            }
        }

        // The implementation's conformance statement (CVP-010, section 5) must stay true.
        let stmt: Value = serde_json::from_str(&read(&root.join("secure-net-conformance.json"))).unwrap();
        if stmt["release"] != reg["release"] || stmt["version"] != version {
            bad("secure-net-conformance.json names a different release".into());
        }
        let mut claimed: Vec<(String, i64)> = stmt["features"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_i64().unwrap_or(0))).collect();
        let mut announced: Vec<(String, i64)> = wire::features::FEATURES.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        claimed.sort();
        announced.sort();
        if claimed != announced {
            bad("secure-net-conformance.json lists different features from wire/features.rs".into());
        }
        for name in names_of(&stmt["profiles"]) {
            match reg["profiles"].as_array().unwrap().iter().find(|x| x["name"] == name.as_str()) {
                None => bad(format!("secure-net-conformance.json claims unknown profile {name}")),
                Some(prof) => {
                    for id in names_of(&prof["parts"]) {
                        if stmt["parts"].get(&id).is_none() {
                            bad(format!("secure-net-conformance.json claims {name} but doesn't list {id}"));
                        }
                    }
                }
            }
        }
        for (id, entry) in stmt["parts"].as_object().unwrap() {
            for v in names_of(&entry["vectors"]) {
                if !parts.get(id).is_some_and(|p| names_of(&p["vectors"]).contains(&format!("vectors/{v}"))) {
                    bad(format!("secure-net-conformance.json: {id} has no vectors {v}"));
                }
            }
        }

        // ---- Generated documents ----
        for (file, text) in generated(&reg, &warnings) {
            if read(&spec(file)) != text {
                bad(format!("spec/{file} is out of date: run cargo run -p secure-net-tools -- standards --write"));
            }
        }
        Outcome { problems, warnings }
    }

    fn names_of(v: &Value) -> Vec<String> {
        v.as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect()
    }

    // ---- What the tool writes ----

    fn cell(v: &str) -> String {
        v.replace('|', "\\|")
    }
    fn table(head: &[&str], rows: Vec<Vec<String>>) -> String {
        let mut out = vec![format!("| {} |", head.join(" | ")), format!("| {} |", head.iter().map(|_| "---").collect::<Vec<_>>().join(" | "))];
        out.extend(rows.into_iter().map(|r| format!("| {} |", r.iter().map(|c| cell(c)).collect::<Vec<_>>().join(" | "))));
        out.join("\n")
    }
    fn code(s: &Value) -> String {
        format!("`{}`", s.as_str().unwrap_or(""))
    }
    fn text(v: &Value) -> String {
        match v {
            Value::Null => String::new(),
            Value::String(s) => s.clone(),
            other => other.to_string(),
        }
    }
    fn note(e: &Value) -> String {
        let status = e["status"].as_str().filter(|s| *s != "active").unwrap_or("").to_string();
        let gf = e["grandfathered"].as_str().map(|g| format!("grandfathered: {g}")).unwrap_or_default();
        [status, gf, text(&e["note"])].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("; ")
    }
    fn codes(v: &Value) -> String {
        v.as_array().into_iter().flatten().map(code).collect::<Vec<_>>().join(", ")
    }

    pub fn generated(reg: &Value, warnings: &[String]) -> Vec<(&'static str, String)> {
        let link = |id: &Value| {
            let id = id.as_str().unwrap_or("");
            match reg["parts"].as_array().unwrap().iter().find(|p| p["id"] == id).and_then(|p| p["doc"].as_str()) {
                Some(doc) => format!("[{id}]({doc})"),
                None => id.to_string(),
            }
        };
        let rows = |list: &str, f: &dyn Fn(&Value) -> Vec<String>| reg[list].as_array().unwrap().iter().map(f).collect::<Vec<_>>();
        let reg_md = [
            "# Registries".to_string(),
            String::new(),
            "Generated from [`registry.json`](registry.json) by `cargo run -p secure-net-tools -- standards --write`. Don't edit this".into(),
            "file: change `registry.json` through a SNIP (CVP-000, section 7), then regenerate it.".into(),
            String::new(),
            format!("Release {}.", reg["release"].as_str().unwrap_or("")),
            String::new(),
            "## Features".into(),
            String::new(),
            table(&["Feature", "Version", "Part", "Notes"], rows("features", &|f| vec![code(&f["name"]), text(&f["version"]), link(&f["part"]), note(f)])),
            String::new(),
            "## Record kinds".into(),
            String::new(),
            "Signed with the label `secure-net/<kind>/v1` (CVP-002).".into(),
            String::new(),
            table(&["Kind", "Part", "Notes"], rows("recordKinds", &|k| vec![code(&k["name"]), link(&k["part"]), note(k)])),
            String::new(),
            "## Ledger events and capabilities".into(),
            String::new(),
            table(&["Event", "Capability needed", "Part", "Notes"], rows("ledgerEvents", &|e| vec![code(&e["name"]), code(&e["capability"]), link(&e["part"]), note(e)])),
            String::new(),
            table(&["Capability", "Part", "Notes"], rows("capabilities", &|c| vec![code(&c["name"]), link(&c["part"]), note(c)])),
            String::new(),
            "## Extension execution models and permissions".into(),
            String::new(),
            table(&["Execution", "Permissions it may ask for", "Part", "Notes"], rows("extensionExecution", &|e| vec![code(&e["name"]), codes(&e["permissions"]), link(&e["part"]), note(e)])),
            String::new(),
            "## Consent actions and vote methods".into(),
            String::new(),
            table(&["Consent action", "Part"], rows("consentActions", &|a| vec![code(&a["name"]), link(&a["part"])])),
            String::new(),
            table(&["Vote method", "Part"], rows("voteMethods", &|a| vec![code(&a["name"]), link(&a["part"])])),
            String::new(),
            "## Social vocabulary".into(),
            String::new(),
            "ActivityStreams 2.0 names (CVP-018), carried as plain canonical JSON rather than JSON-LD.".into(),
            String::new(),
            table(&["Actor type", "Part", "ActivityStreams"], rows("actorTypes", &|t| vec![code(&t["name"]), link(&t["part"]), text(&t["as2"])])),
            String::new(),
            table(&["Activity type", "Part", "ActivityStreams"], rows("activityTypes", &|t| vec![code(&t["name"]), link(&t["part"]), text(&t["as2"])])),
            String::new(),
            table(&["Object type", "Part", "ActivityStreams"], rows("objectTypes", &|t| vec![code(&t["name"]), link(&t["part"]), text(&t["as2"])])),
            String::new(),
            table(&["Address", "Part", "ActivityStreams"], rows("addresses", &|t| vec![code(&t["name"]), link(&t["part"]), text(&t["as2"])])),
            String::new(),
            table(&["Envelope mode", "Part", "What a site can read"], rows("envelopeModes", &|t| vec![code(&t["name"]), link(&t["part"]), text(&t["note"])])),
            String::new(),
            table(&["Lexicon field type", "Part"], rows("lexiconFieldTypes", &|t| vec![code(&t["name"]), link(&t["part"])])),
            String::new(),
            "## Algorithm suites".into(),
            String::new(),
            table(&["Suite", "Used for", "Part", "Notes"], rows("suites", &|s| vec![code(&s["name"]), text(&s["use"]), link(&s["part"]), note(s)])),
            String::new(),
            "## Labels".into(),
            String::new(),
            "Every signature, hash and key derivation is separated by one of these. A label's meaning never changes;".into(),
            "a change means a new version (CVP-000, 4.4). `<...>` marks a variable part.".into(),
            String::new(),
            table(&["Label", "Used for", "Part", "Notes"], rows("labels", &|l| vec![code(&l["label"]), text(&l["use"]), link(&l["part"]), note(l)])),
            String::new(),
            "## Protocol identifiers".into(),
            String::new(),
            table(&["Identifier", "Used for", "Part"], rows("identifiers", &|i| vec![code(&i["name"]), text(&i["use"]), link(&i["part"])])),
            String::new(),
            "## Endpoints".into(),
            String::new(),
            "Defaults; a site may list others in its site document, except the site document itself.".into(),
            String::new(),
            table(&["Name", "Path", "Part", "Notes"], rows("endpoints", &|e| vec![text(&e["name"]), code(&e["path"]), link(&e["part"]), if e["fixed"] == true { "fixed".into() } else { String::new() }])),
            String::new(),
            "## HTTP headers".into(),
            String::new(),
            table(&["Header", "Carries", "Part"], rows("headers", &|h| vec![code(&h["name"]), text(&h["use"]), link(&h["part"])])),
            String::new(),
            "## Conformance profiles".into(),
            String::new(),
            "What each profile requires is in [CVP-010](CVP-010-conformance.md).".into(),
            String::new(),
            table(&["Profile", "Name", "Parts", "For"], rows("profiles", &|p| vec![code(&p["name"]), text(&p["title"]), p["parts"].as_array().unwrap().iter().map(&link).collect::<Vec<_>>().join(", "), text(&p["for"])])),
            String::new(),
        ]
        .join("\n");

        let missing: Vec<String> = reg["parts"].as_array().unwrap().iter().filter(|p| p["status"] != "Reserved" && p["doc"].as_str().is_none()).map(|p| text(&p["id"])).collect();
        let index = [
            "<!-- index:start (generated by cargo run -p secure-net-tools -- standards --write from registry.json; don't edit) -->".to_string(),
            table(&["Part", "Subject", "Status", "Version", "Features", "Code"], rows("parts", &|p| vec![link(&p["id"]), text(&p["title"]), text(&p["status"]), if p["version"] == 0 { String::new() } else { text(&p["version"]) }, codes(&p["features"]), codes(&p["code"])])),
            String::new(),
            if warnings.is_empty() { "Every part has a document.".to_string() } else { format!("**Documentation still to write:** {}. These parts are implemented and tested, but so far the code is their only specification.", missing.join(", ")) },
            "<!-- index:end -->".into(),
        ]
        .join("\n");
        let readme = read(&root().join("spec/README.md"));
        let next = match (readme.find("<!-- index:start"), readme.find("<!-- index:end -->")) {
            (Some(at), Some(end)) if end > at => format!("{}{}{}", &readme[..at], index, &readme[end + "<!-- index:end -->".len()..]),
            _ => readme,
        };
        vec![("REGISTRIES.md", reg_md), ("README.md", next)]
    }

    pub fn run(write: bool) -> ExitCode {
        if write {
            let reg: Value = serde_json::from_str(&read(&root().join("spec/registry.json"))).unwrap();
            let out = check();
            for (file, text) in generated(&reg, &out.warnings) {
                fs::write(root().join("spec").join(file), text).unwrap();
            }
        }
        let out = check();
        for w in &out.warnings {
            println!("note: {w}");
        }
        for p in &out.problems {
            eprintln!("problem: {p}");
        }
        if out.problems.is_empty() {
            println!("\nThe code, registries and documents agree.");
            ExitCode::SUCCESS
        } else {
            println!("\n{} problem(s)", out.problems.len());
            ExitCode::FAILURE
        }
    }
}
