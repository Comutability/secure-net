// Writes secure-net.manifest.json: the version and a SHA-256 of every file an app copies in.
// Apps that keep a copy (Commonveil does, in packages/secure-net) check it against this, so a
// copy can't drift from a release without anyone noticing.
//
//   node scripts/manifest.mjs           write it
//   node scripts/manifest.mjs --check   fail if it's out of date
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const INCLUDE = ["package.json", "README.md", "LICENSE", "src", "spec", "test"];

export function filesOf(dir) {
  const out = [];
  const walk = (rel) => {
    const abs = path.join(dir, rel);
    if (!fs.existsSync(abs)) return;
    if (fs.statSync(abs).isDirectory()) for (const e of fs.readdirSync(abs).sort()) walk(path.posix.join(rel, e));
    else out.push(rel);
  };
  for (const p of INCLUDE) walk(p);
  return out;
}

export function manifestOf(dir) {
  const { version } = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const files = {};
  for (const f of filesOf(dir)) files[f] = crypto.createHash("sha256").update(fs.readFileSync(path.join(dir, f))).digest("base64url");
  return { name: "secure-net", version, files };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const file = path.join(root, "secure-net.manifest.json");
  const want = `${JSON.stringify(manifestOf(root), null, 2)}\n`;
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(file) || fs.readFileSync(file, "utf8") !== want) {
      console.error("secure-net.manifest.json is out of date: run node scripts/manifest.mjs");
      process.exit(1);
    }
    console.log("Manifest is up to date.");
  } else {
    fs.writeFileSync(file, want);
    console.log(`Wrote secure-net.manifest.json (${Object.keys(JSON.parse(want).files).length} files).`);
  }
}
