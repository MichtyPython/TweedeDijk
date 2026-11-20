// Encrypts everything in private/ into vault/ for the website.
//
//   node tools/encrypt.mjs
//
// Asks for username + password (or reads VAULT_USER / VAULT_PASS).
// Subfolders of private/ become categories on the site.
// Unchanged files are not re-encrypted; deleted files are removed from vault/.
// The private/ folder is git-ignored: only encrypted files ever reach GitHub.

import { webcrypto as crypto, createHmac, createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline/promises';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'private');
const VAULT = path.join(ROOT, 'vault');
const FILES = path.join(VAULT, 'files');
const CFG = path.join(VAULT, 'config.json');
const MANIFEST = path.join(VAULT, 'manifest.bin');
const ITERATIONS = 600_000;

const MIME = {
  pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
  webp: 'image/webp', svg: 'image/svg+xml', txt: 'text/plain', md: 'text/markdown', csv: 'text/csv',
  json: 'application/json', html: 'text/html',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};

const exists = (p) => fs.access(p).then(() => true, () => false);

async function credentials() {
  let user = process.env.VAULT_USER, pass = process.env.VAULT_PASS;
  if (user && pass) return { user, pass };
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  user = (await rl.question('Gebruikersnaam: ')).trim();
  pass = await rl.question('Wachtwoord: ');
  rl.close();
  return { user, pass };
}

async function deriveKey(user, pass, cfg) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(user + '\n' + pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: Buffer.from(cfg.salt, 'base64'), iterations: cfg.iterations, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

async function encrypt(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data));
  return Buffer.concat([iv, ct]);
}

async function decrypt(key, buf) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.subarray(0, 12) }, key, buf.subarray(12));
}

async function walk(dir, rel = '') {
  const out = [];
  if (!(await exists(dir))) return out;
  for (const ent of await fs.readdir(dir, { withFileTypes: true })) {
    if (ent.name.startsWith('.')) continue;
    const full = path.join(dir, ent.name), r = rel ? `${rel}/${ent.name}` : ent.name;
    if (ent.isDirectory()) out.push(...await walk(full, r));
    else if (ent.isFile()) out.push({ full, rel: r });
  }
  return out;
}

const reset = process.argv.includes('--reset');
await fs.mkdir(FILES, { recursive: true });
await fs.mkdir(SRC, { recursive: true });

let cfg;
if (!reset && await exists(CFG)) {
  cfg = JSON.parse(await fs.readFile(CFG, 'utf8'));
} else {
  cfg = { v: 1, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS,
          salt: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64') };
  if (reset) for (const f of await fs.readdir(FILES)) await fs.unlink(path.join(FILES, f));
}

const { user, pass } = await credentials();
const key = await deriveKey(user, pass, cfg);

// Guard against typos: the password must open the existing vault.
if (!reset && await exists(MANIFEST)) {
  try { await decrypt(key, await fs.readFile(MANIFEST)); }
  catch {
    console.error('Gebruikersnaam/wachtwoord komt niet overeen met de bestaande kluis.\n' +
                  'Gebruik --reset om alles opnieuw te versleutelen met nieuwe inloggegevens.');
    process.exit(1);
  }
}

const rawKey = Buffer.from(await crypto.subtle.exportKey('raw', key));
const docs = [], keep = new Set();
let added = 0;

for (const f of (await walk(SRC)).sort((a, b) => a.rel.localeCompare(b.rel))) {
  const data = await fs.readFile(f.full);
  const stat = await fs.stat(f.full);
  const hash = createHash('sha256').update(data).digest();
  const id = createHmac('sha256', rawKey).update(hash).digest('hex').slice(0, 32);
  const out = path.join(FILES, `${id}.bin`);
  if (!(await exists(out))) { await fs.writeFile(out, await encrypt(key, data)); added++; }
  keep.add(`${id}.bin`);

  const name = path.basename(f.rel), ext = path.extname(name).slice(1).toLowerCase();
  const dir = path.dirname(f.rel);
  docs.push({
    id, name, ext,
    title: name.replace(/\.[^.]+$/, ''),
    category: dir === '.' ? 'Algemeen' : dir,
    mime: MIME[ext] || 'application/octet-stream',
    size: stat.size,
    modified: stat.mtimeMs,
  });
}

let removed = 0;
for (const f of await fs.readdir(FILES)) if (!keep.has(f)) { await fs.unlink(path.join(FILES, f)); removed++; }

await fs.writeFile(MANIFEST, await encrypt(key, Buffer.from(JSON.stringify({ generated: Date.now(), docs }))));
await fs.writeFile(CFG, JSON.stringify(cfg, null, 2) + '\n');

console.log(`Klaar: ${docs.length} documenten (${added} nieuw versleuteld, ${removed} verwijderd).`);
console.log('Volgende stap: git add -A && git commit -m "Documenten bijgewerkt" && git push');
