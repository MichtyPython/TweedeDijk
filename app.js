// TweedeDijk — client-side encrypted document site on GitHub Pages.
//
// Everything in vault/ is AES-256-GCM encrypted with a key derived (PBKDF2) from
// username + password. Writes (uploads, notes, to-do's, summaries) go straight to the
// GitHub repo through the GitHub API, using a token that is itself stored encrypted
// in vault/secrets.bin. Summaries are generated in the browser with the Claude API.

const REPO = 'MichtyPython/TweedeDijk';
const BRANCH = 'main';
const MODEL = 'claude-opus-5-5';
const SDK_URL = 'https://cdn.jsdelivr.net/npm/@anthropic-ai/sdk@1.6.0/+esm';
const COMMIT_MSG = 'Update vault'; // the repo is public: never put document names in commit messages

const P = {
  config: 'vault/config.json',
  manifest: 'vault/manifest.bin',
  todo: 'vault/todo.bin',
  secrets: 'vault/secrets.bin',
  file: (id) => `vault/files/${id}.bin`,
  summary: (id) => `vault/summaries/${id}.bin`,
};

pdfjsLib.GlobalWorkerOptions.workerSrc =
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const SESSION_KEY = 'td-key';

let key = null;       // CryptoKey (AES-GCM)
let rawKey = null;    // Uint8Array, used for deterministic document ids
let manifest = { docs: [] };
let todo = { persons: [], items: [] };
let secrets = {};     // { anthropicKey, githubToken }
const busy = new Set();          // doc ids being summarized
const fileCache = new Map();     // id -> ArrayBuffer (decrypted)
const summaryCache = new Map();  // id -> summary object

// ---------- small helpers ----------
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'value') e.value = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(2)) if (c != null && c !== false) e.append(c instanceof Node ? c : String(c));
  return e;
}
const pref = {
  get: (k, d) => { try { return localStorage.getItem('td-' + k) ?? d; } catch { return d; } },
  set: (k, v) => { try { localStorage.setItem('td-' + k, v); } catch {} },
};
let toastTimer;
function toast(msg, isError = false) {
  const t = $('#toast');
  t.textContent = msg; t.classList.toggle('err', isError); t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), isError ? 7000 : 3500);
}
const fmtSize = (n) => n > 1e6 ? (n / 1e6).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1e3)) + ' kB';
const fmtDate = (t) => new Date(t).toLocaleDateString('nl-NL', { day: 'numeric', month: 'short', year: 'numeric' });
const fmtDateTime = (t) => new Date(t).toLocaleString('nl-NL', { dateStyle: 'medium', timeStyle: 'short' });
const uid = () => crypto.randomUUID();
const canWrite = () => !!secrets.githubToken;

// ---------- crypto ----------
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
function b64e(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s);
}
async function deriveKey(user, pass, cfg) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(user + '\n' + pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64d(cfg.salt), iterations: cfg.iterations, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function encrypt(u8) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, u8));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return out;
}
async function decrypt(u8) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8.slice(0, 12) }, key, u8.slice(12));
}
const encJson = async (obj) => encrypt(new TextEncoder().encode(JSON.stringify(obj)));
const decJson = async (u8) => JSON.parse(new TextDecoder().decode(await decrypt(u8)));

// Same id scheme as tools/encrypt.mjs: HMAC-SHA256(rawKey, SHA256(content)), 32 hex chars.
async function docId(bytes) {
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  const hk = await crypto.subtle.importKey('raw', rawKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', hk, hash));
  return [...sig].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

// ---------- storage (GitHub API when a token is set, else the static site) ----------
function gh(path, opts = {}, accept = 'application/vnd.github+json', token = secrets.githubToken) {
  const url = `https://api.github.com/repos/${REPO}/contents/${path}` + (opts.method ? '' : `?ref=${BRANCH}`);
  return fetch(url, {
    ...opts, cache: 'no-store',
    headers: { Authorization: `Bearer ${token}`, Accept: accept, 'X-GitHub-Api-Version': '2022-11-28' },
  });
}
async function ghError(r) {
  let msg = `${r.status}`;
  try { msg += ' ' + (await r.json()).message; } catch {}
  return Object.assign(new Error('GitHub: ' + msg), { status: r.status });
}
async function readBin(path) {
  const r = canWrite() ? await gh(path, {}, 'application/vnd.github.raw+json') : await fetch(path, { cache: 'no-cache' });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`Lezen mislukt (${r.status})`);
  return new Uint8Array(await r.arrayBuffer());
}
async function getSha(path, token) {
  const r = await gh(path, {}, 'application/vnd.github.object+json', token);
  if (r.status === 404) return null;
  if (!r.ok) throw await ghError(r);
  return (await r.json()).sha;
}
async function putBin(path, u8, sha, token = secrets.githubToken) {
  const body = { message: COMMIT_MSG, content: b64e(u8), branch: BRANCH };
  if (sha) body.sha = sha;
  const r = await gh(path, { method: 'PUT', body: JSON.stringify(body) }, undefined, token);
  if (!r.ok) throw await ghError(r);
}
async function delBin(path) {
  const sha = await getSha(path);
  if (!sha) return;
  const r = await gh(path, { method: 'DELETE', body: JSON.stringify({ message: COMMIT_MSG, sha, branch: BRANCH }) });
  if (!r.ok && r.status !== 404) throw await ghError(r);
}
async function loadEnc(path, fallback) {
  const bytes = await readBin(path);
  return bytes ? decJson(bytes) : fallback;
}
async function putEnc(path, obj) {
  await putBin(path, await encJson(obj), await getSha(path));
}
// Read-modify-write with retry, so two people editing at once don't overwrite each other.
async function updateEnc(path, fallback, mutate) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const r = await gh(path, {}, 'application/vnd.github.object+json');
    let sha = null, data = structuredClone(fallback);
    if (r.ok) {
      const j = await r.json();
      sha = j.sha;
      const bytes = j.encoding === 'base64' && j.content ? b64d(j.content.replace(/\s/g, '')) : await readBin(path);
      data = await decJson(bytes);
    } else if (r.status !== 404) throw await ghError(r);
    mutate(data);
    try { await putBin(path, await encJson(data), sha); return data; }
    catch (e) { if (e.status === 409 || e.status === 422) continue; throw e; }
  }
  throw new Error('Opslaan mislukt (te veel gelijktijdige wijzigingen). Probeer het opnieuw.');
}
const saveManifest = async (mutate) => { mutate(manifest); renderDocs(); manifest = await updateEnc(P.manifest, { docs: [] }, mutate); renderDocs(); };
const saveTodo = async (mutate) => {
  mutate(todo); renderTodo();
  try { todo = await updateEnc(P.todo, { persons: [], items: [] }, mutate); }
  catch (e) { toast('Opslaan mislukt: ' + e.message, true); todo = await loadEnc(P.todo, todo); }
  renderTodo();
};

async function getFile(d) {
  if (!fileCache.has(d.id)) {
    const bytes = await readBin(P.file(d.id));
    if (!bytes) throw new Error('Bestand niet gevonden (misschien nog niet gepubliceerd).');
    fileCache.set(d.id, await decrypt(bytes));
  }
  return fileCache.get(d.id);
}
async function getSummary(d) {
  if (!summaryCache.has(d.id)) summaryCache.set(d.id, await loadEnc(P.summary(d.id), null));
  return summaryCache.get(d.id);
}

// ---------- login ----------
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('#login-btn'), err = $('#login-error');
  btn.disabled = true; btn.textContent = 'Bezig…'; err.hidden = true;
  try {
    const cfg = await (await fetch(P.config, { cache: 'no-cache' })).json();
    key = await deriveKey($('#user').value.trim(), $('#pass').value, cfg);
    rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    manifest = await loadEnc(P.manifest, null);   // fails if the password is wrong
    if (!manifest) throw new Error('no manifest');
    try { sessionStorage.setItem(SESSION_KEY, b64e(rawKey)); } catch {}
    await afterUnlock();
  } catch (ex) {
    console.warn(ex);
    key = rawKey = null;
    err.textContent = 'Onjuiste gebruikersnaam of wachtwoord.';
    err.hidden = false;
    const card = $('#login-form');
    card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
  } finally {
    btn.disabled = false; btn.textContent = 'Inloggen';
  }
});

async function resumeSession() {
  let saved = null;
  try { saved = sessionStorage.getItem(SESSION_KEY); } catch {}
  if (!saved) return;
  try {
    rawKey = b64d(saved);
    key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', true, ['encrypt', 'decrypt']);
    manifest = await loadEnc(P.manifest, null);
    if (!manifest) throw new Error('no manifest');
    await afterUnlock();
  } catch { try { sessionStorage.removeItem(SESSION_KEY); } catch {} key = rawKey = null; }
}

async function afterUnlock() {
  try { secrets = (await loadEnc(P.secrets, {})) || {}; } catch { secrets = {}; }
  if (canWrite()) {
    try { manifest = await loadEnc(P.manifest, manifest); } catch (e) { console.warn(e); }
  }
  try { todo = await loadEnc(P.todo, { persons: [], items: [] }); } catch { todo = { persons: [], items: [] }; }
  $('#login').hidden = true;
  $('#app').hidden = false;
  updateWriteState();
  renderDocs();
  renderTodo();
}

$('#logout').addEventListener('click', () => {
  try { sessionStorage.removeItem(SESSION_KEY); } catch {}
  location.reload();
});

function updateWriteState(root = document) {
  $('#readonly-banner').hidden = canWrite();
  for (const b of $$('[data-write]', root)) {
    b.disabled = !canWrite();
    if (!canWrite()) b.title = 'Stel eerst een GitHub-token in (Instellingen)';
  }
}

// ---------- navigation ----------
function show(view) {
  for (const v of $$('.view')) v.hidden = v.id !== `view-${view}`;
  for (const b of $$('#tabs button')) b.classList.toggle('active', b.dataset.view === view || (view === 'viewer' && b.dataset.view === 'docs'));
  window.scrollTo(0, 0);
}
for (const b of $$('#tabs button')) {
  b.addEventListener('click', async () => {
    show(b.dataset.view);
    if (!canWrite()) return;
    try {   // pick up changes made by others
      if (b.dataset.view === 'docs') { manifest = await loadEnc(P.manifest, manifest); renderDocs(); }
      if (b.dataset.view === 'todo') { todo = await loadEnc(P.todo, todo); renderTodo(); }
    } catch (e) { console.warn(e); }
  });
}

// ---------- modal ----------
const modal = $('#modal');
function openModal({ title, body, actions = [], wide = false }) {
  const inner = $('.modal-inner', modal);
  inner.replaceChildren(
    el('div', { class: 'modal-head' }, el('h2', {}, title),
      el('button', { class: 'ghost small', onclick: closeModal, 'aria-label': 'Sluiten' }, '✕')),
    el('div', { class: 'modal-body' }, body),
    el('div', { class: 'modal-foot' }, actions));
  modal.classList.toggle('wide', wide);
  if (!modal.open) modal.showModal();
  updateWriteState(modal);
}
function closeModal() { if (modal.open) modal.close(); }
modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });

// ---------- documents ----------
let layout = pref.get('layout', 'tiles');
for (const b of $$('[data-layout]')) {
  b.addEventListener('click', () => { layout = b.dataset.layout; pref.set('layout', layout); renderDocs(); });
}
$('#doc-filter').addEventListener('input', () => renderDocs());

function renderDocs() {
  for (const b of $$('[data-layout]')) b.classList.toggle('active', b.dataset.layout === layout);
  const q = $('#doc-filter').value.trim().toLowerCase();
  const docs = [...manifest.docs]
    .sort((a, b) => (b.added || b.modified || 0) - (a.added || a.modified || 0))
    .filter((d) => !q || [d.title, d.ai?.uitleg, ...(d.ai?.inhoud || [])].join(' ').toLowerCase().includes(q));
  $('#doc-empty').hidden = manifest.docs.length > 0;

  const tiles = $('#doc-tiles'), table = $('#doc-table');
  tiles.hidden = layout !== 'tiles'; table.hidden = layout !== 'list' || !manifest.docs.length;
  if (layout === 'tiles') tiles.replaceChildren(...docs.map(docTile));
  else $('tbody', table).replaceChildren(...docs.map(docRow));
  updateWriteState($('#view-docs'));
}

function docRow(d) {
  const n = d.notes?.length || 0;
  return el('tr', { onclick: () => openDoc(d) },
    el('td', { class: 'name' }, d.title),
    el('td', {}, busy.has(d.id) ? 'Claude is bezig…' : (d.ai?.inhoud || []).join(', ') || '—'),
    el('td', {}, fmtDate(d.added || d.modified)),
    el('td', {}, fmtSize(d.size)),
    el('td', {}, n ? String(n) : ''));
}

function docTile(d) {
  const ai = d.ai, isPdf = d.ext === 'pdf', notes = d.notes || [];
  const tile = el('article', { class: 'doc-tile' },
    el('header', {},
      el('div', { style: 'flex:1;min-width:200px' },
        el('h3', {}, d.title),
        el('div', { class: 'meta' }, `${d.ext.toUpperCase()} · ${fmtSize(d.size)} · toegevoegd ${fmtDate(d.added || d.modified)}`)),
      el('div', { class: 'actions' },
        el('button', { class: 'ghost small', onclick: () => openDoc(d) }, 'Openen'),
        el('button', { class: 'ghost small', 'data-write': true, onclick: () => noteDialog(d) }, '+ Notitie'),
        isPdf && el('button', { class: 'ghost small', 'data-write': true, disabled: busy.has(d.id), onclick: () => refreshDialog(d) }, '↻ Vernieuwen'),
        el('button', { class: 'danger small', 'data-write': true, onclick: () => deleteDoc(d) }, 'Verwijderen'))));

  if (busy.has(d.id)) {
    tile.append(el('div', { class: 'busy' }, el('span', { class: 'spinner' }), 'Claude leest het document…'));
  } else if (!ai) {
    tile.append(el('p', { class: 'muted', style: 'margin:0' }, 'Nog geen samenvatting. ',
      isPdf && el('button', { class: 'linkish', 'data-write': true, onclick: () => refreshDialog(d) }, 'Laat Claude samenvatten')));
  } else {
    tile.append(
      el('div', {}, el('div', { class: 'field-label' }, 'Inhoud'),
        el('div', { class: 'keywords' }, (ai.inhoud || []).map((w) => el('span', {}, w)))),
      el('div', {}, el('div', { class: 'field-label' }, 'Wat is het'), el('div', {}, ai.uitleg)),
      el('div', { class: 'summary-box', role: 'button', tabindex: '0', onclick: () => openSummary(d),
                  onkeydown: (e) => { if (e.key === 'Enter') openSummary(d); } },
        el('div', { class: 'field-label' }, 'Samenvatting'),
        el('p', {}, ai.kort),
        el('span', { class: 'more' }, 'Volledige samenvatting openen →')));
  }
  if (notes.length) {
    tile.append(el('div', { class: 'tile-foot' },
      el('button', { class: 'linkish', onclick: () => openSummary(d) }, `📝 ${notes.length} ${notes.length === 1 ? 'notitie' : 'notities'}`)));
  }
  return tile;
}

let viewerToken = 0;
async function openDoc(d) {
  closeModal();
  const token = ++viewerToken;
  show('viewer');
  $('#viewer-title').textContent = d.title;
  const body = $('#viewer-body');
  body.replaceChildren(el('p', { class: 'muted' }, 'Ontsleutelen…'));
  let buf;
  try { buf = await getFile(d); } catch (e) { body.replaceChildren(el('p', { class: 'error' }, e.message)); return; }
  if (token !== viewerToken) return;
  const url = URL.createObjectURL(new Blob([buf], { type: d.mime }));
  const dl = $('#download'); dl.href = url; dl.download = d.name;
  body.replaceChildren();
  if (d.ext === 'pdf') {
    const pdf = await pdfjsLib.getDocument({ data: new Uint8Array(buf.slice(0)) }).promise;
    const width = Math.min(body.clientWidth || 800, 1000);
    for (let i = 1; i <= pdf.numPages; i++) {
      if (token !== viewerToken) return;
      const page = await pdf.getPage(i);
      const scale = (width / page.getViewport({ scale: 1 }).width) * (window.devicePixelRatio || 1);
      const vp = page.getViewport({ scale });
      const c = el('canvas'); c.width = vp.width; c.height = vp.height; c.style.width = width + 'px';
      body.append(c);
      await page.render({ canvasContext: c.getContext('2d'), viewport: vp }).promise;
    }
  } else if (d.mime?.startsWith('image/')) {
    body.append(el('img', { src: url, alt: d.title, style: 'max-width:100%' }));
  } else {
    body.append(el('p', { class: 'muted' }, 'Geen voorbeeld beschikbaar voor dit bestandstype. Gebruik Download.'));
  }
}
$('#back').addEventListener('click', () => show('docs'));

// ----- summary popup -----
async function openSummary(d) {
  d = manifest.docs.find((x) => x.id === d.id) || d;
  openModal({ title: d.title, wide: true, body: el('p', { class: 'muted' }, 'Laden…') });
  let s = null;
  try { s = d.ai ? await getSummary(d) : null; } catch (e) { console.warn(e); }
  const notes = [...(d.notes || [])].sort((a, b) => b.t - a.t);
  const body = [];
  if (notes.length) {
    body.push(el('div', { class: 'notes-block' },
      el('div', { class: 'field-label' }, 'Notities'),
      notes.map((n) => el('div', { class: 'note' },
        el('p', {}, n.text, el('small', {}, `${n.author || 'Anoniem'} · ${fmtDateTime(n.t)}`)),
        el('button', { class: 'ghost small', 'data-write': true, onclick: () => deleteNote(d, n.id) }, 'Verwijder')))));
  }
  if (s?.samenvatting) {
    if (d.ai?.uitleg) body.push(el('p', { class: 'muted', style: 'margin:0' }, d.ai.uitleg));
    const md = el('div', { class: 'markdown' });
    md.innerHTML = DOMPurify.sanitize(marked.parse(s.samenvatting));
    body.push(md);
    body.push(el('div', { class: 'prompt-used' },
      `Gegenereerd door Claude op ${fmtDateTime(s.generatedAt)}`,
      s.prompt ? ` · Instructies: “${s.prompt}”` : ''));
  } else {
    body.push(el('p', { class: 'muted' }, 'Nog geen samenvatting voor dit document.'));
  }
  openModal({
    title: d.title, wide: true, body,
    actions: [
      el('button', { class: 'ghost', 'data-write': true, onclick: () => noteDialog(d, true) }, '+ Notitie'),
      d.ext === 'pdf' && el('button', { class: 'ghost', 'data-write': true, onclick: () => refreshDialog(d) }, '↻ Vernieuwen'),
      el('button', { class: 'ghost', onclick: () => openDoc(d) }, 'Document openen'),
      el('button', { onclick: closeModal }, 'Sluiten'),
    ],
  });
}

// ----- notes -----
function personSelect(id, includeNone, noneLabel = 'Anoniem', selected = '') {
  return el('select', { id },
    includeNone && el('option', { value: '' }, noneLabel),
    todo.persons.map((p) => el('option', { value: p, selected: p === selected }, p)));
}
function noteDialog(d, backToSummary = false) {
  const text = el('textarea', { rows: '5', placeholder: 'Schrijf een notitie…' });
  const author = personSelect('note-author', true, 'Anoniem', pref.get('me', ''));
  const save = el('button', { 'data-write': true, onclick: async () => {
    const t = text.value.trim(); if (!t) return text.focus();
    save.disabled = true; save.textContent = 'Opslaan…';
    pref.set('me', author.value);
    const note = { id: uid(), text: t, author: author.value, t: Date.now() };
    try {
      await saveManifest((m) => { const x = m.docs.find((y) => y.id === d.id); if (x && !(x.notes ||= []).some((n) => n.id === note.id)) x.notes.push(note); });
      toast('Notitie opgeslagen.');
      backToSummary ? openSummary(d) : closeModal();
    } catch (e) { toast('Opslaan mislukt: ' + e.message, true); save.disabled = false; save.textContent = 'Opslaan'; }
  } }, 'Opslaan');
  openModal({
    title: `Notitie bij “${d.title}”`,
    body: [el('label', {}, 'Notitie', text), el('label', {}, 'Van', author),
           el('p', { class: 'hint' }, 'Notities staan bovenaan de samenvatting van dit document.')],
    actions: [el('button', { class: 'ghost', onclick: () => (backToSummary ? openSummary(d) : closeModal()) }, 'Annuleren'), save],
  });
  text.focus();
}
async function deleteNote(d, noteId) {
  if (!confirm('Deze notitie verwijderen?')) return;
  try {
    await saveManifest((m) => { const x = m.docs.find((y) => y.id === d.id); if (x) x.notes = (x.notes || []).filter((n) => n.id !== noteId); });
    openSummary(d);
  } catch (e) { toast('Verwijderen mislukt: ' + e.message, true); }
}

async function deleteDoc(d) {
  if (!confirm(`“${d.title}” verwijderen? Dit verwijdert ook de samenvatting en notities.`)) return;
  try {
    await delBin(P.file(d.id));
    await delBin(P.summary(d.id));
    await saveManifest((m) => { m.docs = m.docs.filter((x) => x.id !== d.id); });
    fileCache.delete(d.id); summaryCache.delete(d.id);
    toast('Document verwijderd.');
  } catch (e) { toast('Verwijderen mislukt: ' + e.message, true); }
}

// ----- add PDF -----
$('#add-pdf').addEventListener('click', () => {
  const input = el('input', { type: 'file', accept: 'application/pdf,.pdf', multiple: true });
  const hasKey = !!secrets.anthropicKey;
  const doSum = el('input', { type: 'checkbox', checked: hasKey, disabled: !hasKey });
  const instr = el('textarea', { rows: '3', placeholder: 'Optioneel: instructies voor de samenvatting, bijv. “let vooral op kosten en planning”' });
  const instrWrap = el('label', {}, 'Instructies voor Claude (optioneel)', instr);
  instrWrap.hidden = !hasKey;
  doSum.addEventListener('change', () => (instrWrap.hidden = !doSum.checked));
  const list = el('ul', { class: 'file-list' });
  const go = el('button', { 'data-write': true }, 'Uploaden');
  const cancel = el('button', { class: 'ghost', onclick: closeModal }, 'Annuleren');

  go.addEventListener('click', async () => {
    const files = [...input.files];
    if (!files.length) return toast('Kies eerst een of meer PDF-bestanden.', true);
    go.disabled = cancel.disabled = input.disabled = true; go.textContent = 'Bezig…';
    const added = []; let failed = 0;
    for (const f of files) {
      const li = el('li', {}, `${f.name}: versleutelen…`); list.append(li);
      try {
        const bytes = new Uint8Array(await f.arrayBuffer());
        if (bytes.length > 90e6) throw new Error('te groot (max 90 MB)');
        const id = await docId(bytes);
        if (manifest.docs.some((x) => x.id === id)) { li.textContent = `${f.name}: staat er al`; continue; }
        const enc = await encrypt(bytes);
        li.textContent = `${f.name}: uploaden…`;
        await putBin(P.file(id), enc, await getSha(P.file(id)));
        const doc = { id, name: f.name, title: f.name.replace(/\.[^.]+$/, ''), ext: 'pdf', mime: 'application/pdf',
                      size: f.size, added: Date.now(), notes: [] };
        await saveManifest((m) => { if (!m.docs.some((x) => x.id === id)) m.docs.push(doc); });
        fileCache.set(id, bytes.buffer);
        added.push(doc);
        li.textContent = `${f.name}: klaar`; li.className = 'ok';
      } catch (e) {
        failed++; li.textContent = `${f.name}: mislukt — ${e.message}`; li.className = 'err';
      }
    }
    if (!failed) closeModal();
    else { go.textContent = 'Klaar'; cancel.disabled = false; cancel.textContent = 'Sluiten'; }
    if (added.length) toast(`${added.length} document(en) toegevoegd.`);
    if (doSum.checked) for (const d of added) await summarize(d, instr.value.trim());
  });

  openModal({
    title: 'PDF toevoegen',
    body: [
      el('label', {}, "PDF-bestand(en)", input),
      el('label', { class: 'check' }, doSum, 'Laat Claude een samenvatting maken'),
      !hasKey && el('p', { class: 'hint' }, 'Samenvatten kan pas als er een Claude API-sleutel is ingesteld (Instellingen).'),
      instrWrap, list,
      el('p', { class: 'hint' }, 'Bestanden worden in je browser versleuteld voordat ze naar GitHub gaan.'),
    ],
    actions: [cancel, go],
  });
});

// ----- Claude -----
const SUMMARY_SCHEMA = {
  type: 'object',
  properties: {
    inhoud: { type: 'array', items: { type: 'string' }, description: '3 tot 6 trefwoorden (elk 1 tot 3 woorden) die de inhoud typeren' },
    uitleg: { type: 'string', description: '1 à 2 zinnen: wat voor document dit is' },
    kort: { type: 'string', description: 'korte samenvatting van 2 à 3 zinnen' },
    samenvatting: { type: 'string', description: 'volledige samenvatting in Markdown' },
  },
  required: ['inhoud', 'uitleg', 'kort', 'samenvatting'],
  additionalProperties: false,
};
const SYSTEM_PROMPT =
  'Je vat documenten samen voor een kleine Nederlandse werkgroep (TweedeDijk). ' +
  'Schrijf altijd in helder, zakelijk Nederlands. Baseer je uitsluitend op wat er in het document staat; ' +
  'als iets niet in het document staat, verzin het dan niet.';

function userPrompt(d, extra) {
  return [
    `Analyseer het bijgevoegde document (“${d.name}”) en vul de velden in:`,
    '- inhoud: 3 tot 6 trefwoorden (elk 1 tot 3 woorden) die de inhoud typeren.',
    '- uitleg: 1 à 2 zinnen over wat voor document dit is (soort document, afzender of doel, datum als die bekend is).',
    '- kort: een korte samenvatting van 2 à 3 zinnen voor op de overzichtstegel.',
    '- samenvatting: een volledige samenvatting in Markdown met kopjes en opsommingstekens: de hoofdpunten, ' +
      'belangrijke cijfers, data en besluiten, en eventuele actiepunten of open vragen.',
    extra ? `\nExtra instructies van de gebruiker (gelden vooral voor de samenvatting):\n${extra}` : '',
  ].join('\n');
}

async function askClaude(d, pdfBytes, extra) {
  if (pdfBytes.length > 30e6) throw new Error('PDF is te groot voor Claude (max ongeveer 30 MB).');
  const { default: Anthropic } = await import(SDK_URL);
  const client = new Anthropic({ apiKey: secrets.anthropicKey, dangerouslyAllowBrowser: true });
  const stream = client.beta.messages.stream({
    model: MODEL,
    max_tokens: 64000,
    betas: ['server-side-fallback-2026-07-01'],
    fallbacks: 'default',
    output_config: { effort: 'medium', format: { type: 'json_schema', schema: SUMMARY_SCHEMA } },
    system: SYSTEM_PROMPT,
    messages: [{
      role: 'user',
      content: [
        { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: b64e(pdfBytes) } },
        { type: 'text', text: userPrompt(d, extra) },
      ],
    }],
  });
  const msg = await stream.finalMessage();
  if (msg.stop_reason === 'refusal') throw new Error('Claude heeft dit document geweigerd.');
  if (msg.stop_reason === 'max_tokens') throw new Error('het antwoord werd afgebroken (te lang).');
  const text = msg.content.filter((b) => b.type === 'text').map((b) => b.text).join('');
  return { ...JSON.parse(text), model: msg.model };
}

async function summarize(d, extra = '') {
  if (!secrets.anthropicKey) return toast('Stel eerst een Claude API-sleutel in (Instellingen).', true);
  busy.add(d.id); renderDocs();
  try {
    const bytes = new Uint8Array(await getFile(d));
    const r = await askClaude(d, bytes, extra);
    const now = Date.now();
    const summary = { samenvatting: r.samenvatting, prompt: extra, generatedAt: now, model: r.model };
    await putEnc(P.summary(d.id), summary);
    summaryCache.set(d.id, summary);
    busy.delete(d.id);
    await saveManifest((m) => {
      const x = m.docs.find((y) => y.id === d.id);
      if (x) x.ai = { inhoud: r.inhoud, uitleg: r.uitleg, kort: r.kort, prompt: extra, generatedAt: now };
    });
    toast(`Samenvatting klaar: ${d.title}`);
  } catch (e) {
    console.error(e);
    const why = e.status === 401 ? 'de Claude API-sleutel is ongeldig (zie Instellingen).'
      : e.status === 429 ? 'te veel verzoeken of tegoed op; probeer het later opnieuw.'
      : e.status === 400 && /credit|balance/i.test(e.message) ? 'onvoldoende API-tegoed op console.anthropic.com.'
      : e.message;
    toast(`Samenvatten mislukt (${d.title}): ${why}`, true);
  } finally {
    busy.delete(d.id); renderDocs();
  }
}

function refreshDialog(d) {
  d = manifest.docs.find((x) => x.id === d.id) || d;
  if (!secrets.anthropicKey) return toast('Stel eerst een Claude API-sleutel in (Instellingen).', true);
  const instr = el('textarea', { rows: '4', placeholder: 'Bijv. “Maak de samenvatting korter” of “Focus op de financiële gevolgen”' });
  instr.value = d.ai?.prompt || '';
  openModal({
    title: d.ai ? 'Samenvatting vernieuwen' : 'Samenvatting maken',
    body: [
      el('p', { class: 'hint' }, `Claude leest “${d.title}” opnieuw en maakt de inhoud, uitleg en samenvatting opnieuw. De huidige versie wordt vervangen.`),
      el('label', {}, 'Instructies voor de samenvatting (optioneel)', instr),
    ],
    actions: [
      el('button', { class: 'ghost', onclick: closeModal }, 'Annuleren'),
      el('button', { 'data-write': true, onclick: () => { closeModal(); summarize(d, instr.value.trim()); } },
        d.ai ? '↻ Opnieuw genereren' : 'Genereren'),
    ],
  });
  instr.focus();
}

// ---------- settings ----------
for (const b of [$('#settings-btn'), ...$$('[data-open-settings]')]) b.addEventListener('click', openSettings);
function openSettings() {
  const ak = el('input', { type: 'password', autocomplete: 'off', placeholder: secrets.anthropicKey ? 'Ingesteld ✓ (laat leeg om te behouden)' : 'sk-ant-…' });
  const gt = el('input', { type: 'password', autocomplete: 'off', placeholder: secrets.githubToken ? 'Ingesteld ✓ (laat leeg om te behouden)' : 'github_pat_…' });
  const save = el('button', {}, 'Opslaan');
  save.addEventListener('click', async () => {
    const next = { ...secrets };
    if (ak.value.trim()) next.anthropicKey = ak.value.trim();
    if (gt.value.trim()) next.githubToken = gt.value.trim();
    if (!next.githubToken) return toast('Een GitHub-token is nodig om iets op te slaan.', true);
    save.disabled = true; save.textContent = 'Controleren…';
    try {
      const r = await fetch(`https://api.github.com/repos/${REPO}`, { headers: { Authorization: `Bearer ${next.githubToken}` }, cache: 'no-store' });
      if (!r.ok) throw new Error('GitHub-token werkt niet (' + r.status + ').');
      const repo = await r.json();
      if (!repo.permissions?.push) throw new Error('GitHub-token heeft geen schrijfrechten op de repo.');
      await putBin(P.secrets, await encJson(next), await getSha(P.secrets, next.githubToken), next.githubToken);
      secrets = next;
      updateWriteState(); renderDocs(); renderTodo();
      closeModal(); toast('Instellingen opgeslagen.');
    } catch (e) { toast(e.message, true); save.disabled = false; save.textContent = 'Opslaan'; }
  });
  openModal({
    title: 'Instellingen',
    body: [
      el('label', {}, 'Claude API-sleutel', ak),
      el('p', { class: 'hint' }, 'Maak een sleutel op console.anthropic.com → API keys. Kosten gaan via het tegoed van dat account.'),
      el('label', {}, 'GitHub-token (fine-grained, alleen deze repo, Contents: read & write)', gt),
      el('p', { class: 'hint' }, 'Beide worden versleuteld met de inloggegevens opgeslagen, zodat iedereen die kan inloggen ze kan gebruiken.'),
    ],
    actions: [el('button', { class: 'ghost', onclick: closeModal }, 'Annuleren'), save],
  });
}

// ---------- to-do ----------
const DAY = 86400000;
const today = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d; };
const daysLeft = (s) => Math.round((new Date(s + 'T00:00') - today()) / DAY);
const IMP = { 3: 'Hoog', 2: 'Normaal', 1: 'Laag' };

$('#todo-sort').value = pref.get('todo-sort', 'urgency');
$('#todo-show-done').checked = pref.get('todo-done', '0') === '1';
$('#todo-sort').addEventListener('change', (e) => { pref.set('todo-sort', e.target.value); renderTodo(); });
$('#todo-filter').addEventListener('change', (e) => { pref.set('todo-person', e.target.value); renderTodo(); });
$('#todo-show-done').addEventListener('change', (e) => { pref.set('todo-done', e.target.checked ? '1' : '0'); renderTodo(); });

function fillSelect(sel, first, value) {
  sel.replaceChildren(first, ...todo.persons.map((p) => el('option', { value: p }, p)));
  sel.value = [...sel.options].some((o) => o.value === value) ? value : first.value;
}

function renderTodo() {
  fillSelect($('#todo-person'), el('option', { value: '' }, 'Niemand'), $('#todo-person').value);
  fillSelect($('#todo-filter'), el('option', { value: '*' }, 'Iedereen'), pref.get('todo-person', '*'));
  const who = $('#todo-filter').value, showDone = $('#todo-show-done').checked, sort = $('#todo-sort').value;
  const dl = (i) => (i.deadline ? new Date(i.deadline + 'T00:00').getTime() : Infinity);
  const items = todo.items
    .filter((i) => (who === '*' || i.person === who) && (showDone || !i.done))
    .sort((a, b) => (a.done - b.done)
      || (sort === 'importance' ? (b.importance - a.importance) || (dl(a) - dl(b)) : (dl(a) - dl(b)) || (b.importance - a.importance))
      || (a.created - b.created));
  $('#todo-list').replaceChildren(...items.map(todoItem));
  $('#todo-empty').hidden = items.length > 0;
  updateWriteState($('#view-todo'));
}

function todoItem(i) {
  const meta = [];
  if (i.person) meta.push(el('span', { class: 'pill' }, '👤 ' + i.person));
  if (i.deadline) {
    const n = daysLeft(i.deadline);
    const when = n < 0 ? `${-n} dag${n === -1 ? '' : 'en'} te laat` : n === 0 ? 'vandaag' : n === 1 ? 'morgen' : `over ${n} dagen`;
    const cls = i.done ? 'pill' : n < 0 ? 'pill overdue' : n <= 3 ? 'pill soon' : 'pill';
    meta.push(el('span', { class: cls }, `📅 ${new Date(i.deadline + 'T00:00').toLocaleDateString('nl-NL', { day: 'numeric', month: 'short' })} · ${when}`));
  }
  meta.push(el('span', { class: 'pill' }, IMP[i.importance] || 'Normaal'));
  const cb = el('input', { type: 'checkbox', checked: i.done, 'data-write': true, 'aria-label': 'Afgerond',
    onchange: (e) => { const done = e.target.checked; saveTodo((t) => { const x = t.items.find((y) => y.id === i.id); if (x) x.done = done; }); } });
  return el('li', { class: `todo-item imp-${i.importance}${i.done ? ' done' : ''}` },
    cb,
    el('div', {}, el('div', { class: 't-title' }, i.title), el('div', { class: 't-meta' }, meta)),
    el('div', { class: 'actions' },
      el('button', { class: 'ghost small', 'data-write': true, onclick: () => editTodo(i) }, 'Bewerk'),
      el('button', { class: 'danger small', 'data-write': true, onclick: () => {
        if (confirm(`“${i.title}” verwijderen?`)) saveTodo((t) => { t.items = t.items.filter((y) => y.id !== i.id); });
      } }, '✕')));
}

$('#todo-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const item = {
    id: uid(), title: $('#todo-title').value.trim(), person: $('#todo-person').value,
    deadline: $('#todo-deadline').value, importance: Number($('#todo-importance').value),
    done: false, created: Date.now(),
  };
  if (!item.title) return;
  $('#todo-title').value = ''; $('#todo-deadline').value = '';
  saveTodo((t) => { if (!t.items.some((x) => x.id === item.id)) t.items.push(item); });
});

function editTodo(i) {
  const title = el('input', { value: i.title });
  const person = personSelect('edit-person', true, 'Niemand', i.person);
  const deadline = el('input', { type: 'date', value: i.deadline || '' });
  const imp = el('select', {}, [3, 2, 1].map((v) => el('option', { value: String(v), selected: v === i.importance }, IMP[v])));
  openModal({
    title: 'Taak bewerken',
    body: [el('label', {}, 'Taak', title), el('label', {}, 'Persoon', person),
           el('label', {}, 'Deadline', deadline), el('label', {}, 'Belangrijkheid', imp)],
    actions: [
      el('button', { class: 'ghost', onclick: closeModal }, 'Annuleren'),
      el('button', { 'data-write': true, onclick: () => {
        const v = { title: title.value.trim() || i.title, person: person.value, deadline: deadline.value, importance: Number(imp.value) };
        closeModal();
        saveTodo((t) => { const x = t.items.find((y) => y.id === i.id); if (x) Object.assign(x, v); });
      } }, 'Opslaan'),
    ],
  });
}

$('#manage-persons').addEventListener('click', personsDialog);
function personsDialog() {
  const name = el('input', { placeholder: 'Naam' });
  const add = el('button', { 'data-write': true }, 'Toevoegen');
  const chips = el('div', { class: 'person-chips' });
  const draw = () => {
    chips.replaceChildren(...todo.persons.map((p) => el('span', {}, p,
      el('button', { 'data-write': true, 'aria-label': `${p} verwijderen`, onclick: () => {
        if (!confirm(`${p} verwijderen? Taken van ${p} blijven bestaan.`)) return;
        saveTodo((t) => { t.persons = t.persons.filter((x) => x !== p); }).then(draw);
        draw();
      } }, '✕'))));
    if (!todo.persons.length) chips.append(el('span', { class: 'muted', style: 'border:0;background:none;padding:0' }, 'Nog geen personen.'));
    updateWriteState(modal);
  };
  const doAdd = () => {
    const n = name.value.trim(); if (!n) return;
    if (todo.persons.includes(n)) return toast(`${n} bestaat al.`, true);
    name.value = '';
    saveTodo((t) => { if (!t.persons.includes(n)) t.persons.push(n); t.persons.sort((a, b) => a.localeCompare(b, 'nl')); }).then(draw);
    draw();
  };
  add.addEventListener('click', doAdd);
  name.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); doAdd(); } });
  openModal({
    title: 'Personen',
    body: [el('div', { class: 'row' }, name, add), chips,
           el('p', { class: 'hint' }, 'Personen kun je aan taken koppelen en als afzender van notities kiezen.')],
    actions: [el('button', { onclick: closeModal }, 'Klaar')],
  });
  draw();
}

resumeSession();
