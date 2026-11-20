// Encrypts everything in private/ into vault/ for the website.
//
//   node tools/encrypt.mjs
//
// Asks for username + password (or reads VAULT_USER / VAULT_PASS).
// Adds every file in private/ that is not yet on the site. Documents added through the
// website are kept. Run `git pull` first, because the website commits to the repo too.
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

await fs.mkdir(FILES, { recursive: true });
await fs.mkdir(SRC, { recursive: true });

let cfg;
if (await exists(CFG)) {
  cfg = JSON.parse(await fs.readFile(CFG, 'utf8'));
} else {
  cfg = { v: 1, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS,
          salt: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64') };
}

const { user, pass } = await credentials();
const key = await deriveKey(user, pass, cfg);

// The password must open the existing vault (guards against typos).
let manifest = { docs: [] };
if (await exists(MANIFEST)) {
  try { manifest = JSON.parse(Buffer.from(await decrypt(key, await fs.readFile(MANIFEST))).toString('utf8')); }
  catch {
    console.error('Gebruikersnaam/wachtwoord komt niet overeen met de bestaande kluis.');
    process.exit(1);
  }
}

// Additive import: documents added on the website (and their notes/summaries) are kept.
const rawKey = Buffer.from(await crypto.subtle.exportKey('raw', key));
let added = 0;

for (const f of (await walk(SRC)).sort((a, b) => a.rel.localeCompare(b.rel))) {
  const data = await fs.readFile(f.full);
  const stat = await fs.stat(f.full);
  const hash = createHash('sha256').update(data).digest();
  const id = createHmac('sha256', rawKey).update(hash).digest('hex').slice(0, 32);
  if (manifest.docs.some((d) => d.id === id)) continue;
  await fs.writeFile(path.join(FILES, `${id}.bin`), await encrypt(key, data));
  const name = path.basename(f.rel), ext = path.extname(name).slice(1).toLowerCase();
  manifest.docs.push({
    id, name, ext,
    title: name.replace(/\.[^.]+$/, ''),
    mime: MIME[ext] || 'application/octet-stream',
    size: stat.size,
    added: Date.now(),
    notes: [],
  });
  added++;
}

await fs.writeFile(MANIFEST, await encrypt(key, Buffer.from(JSON.stringify(manifest))));
await fs.writeFile(CFG, JSON.stringify(cfg, null, 2) + '\n');

console.log(`Klaar: ${added} nieuwe documenten toegevoegd (${manifest.docs.length} in totaal).`);
console.log('Volgende stap: git add -A && git commit -m "Update vault" && git push');
