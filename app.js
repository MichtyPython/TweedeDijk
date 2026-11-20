// TweedeDijk — client-side encrypted document vault.
// Every file in vault/ is AES-256-GCM encrypted with a key derived (PBKDF2) from
// username + password. Nothing readable is stored on the server.

pdfjsLib.GlobalWorkerOptions.workerSrc =
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

const $ = (s) => document.querySelector(s);
const SESSION_KEY = 'td-key';
const NOTES_KEY = 'td-notes';

let key = null;          // CryptoKey
let manifest = null;     // { docs: [...] }
let activeCat = 'Alles';
const fileCache = new Map();   // id -> ArrayBuffer (decrypted)
let analysis = null;           // { [id]: { pages: [text], words } }

// ---------- crypto ----------
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64e = (u8) => btoa(String.fromCharCode(...u8));

async function deriveKey(user, pass, cfg) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(user + '\n' + pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64d(cfg.salt), iterations: cfg.iterations, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
}

async function decrypt(buf) {
  const u8 = new Uint8Array(buf);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8.slice(0, 12) }, key, u8.slice(12));
}

async function fetchBin(url) {
  const r = await fetch(url, { cache: 'no-cache' });
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return r.arrayBuffer();
}

async function loadManifest() {
  const plain = await decrypt(await fetchBin('vault/manifest.bin'));
  return JSON.parse(new TextDecoder().decode(plain));
}

async function getFile(doc) {
  if (!fileCache.has(doc.id)) fileCache.set(doc.id, await decrypt(await fetchBin(`vault/files/${doc.id}.bin`)));
  return fileCache.get(doc.id);
}

// ---------- login ----------
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('#login-btn'), err = $('#login-error');
  btn.disabled = true; btn.textContent = 'Bezig…'; err.hidden = true;
  try {
    const cfg = await (await fetch('vault/config.json', { cache: 'no-cache' })).json();
    key = await deriveKey($('#user').value.trim(), $('#pass').value, cfg);
    manifest = await loadManifest();
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    try { sessionStorage.setItem(SESSION_KEY, b64e(raw)); } catch {}
    start();
  } catch (ex) {
    console.warn(ex);
    key = null;
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
    key = await crypto.subtle.importKey('raw', b64d(saved), 'AES-GCM', true, ['decrypt']);
    manifest = await loadManifest();
    start();
  } catch { try { sessionStorage.removeItem(SESSION_KEY); } catch {} key = null; }
}

$('#logout').addEventListener('click', () => {
  try { sessionStorage.removeItem(SESSION_KEY); } catch {}
  location.reload();
});

function start() {
  $('#login').hidden = true;
  $('#app').hidden = false;
  renderCats();
  renderDocs();
  renderNotes();
}

// ---------- navigation ----------
function show(view) {
  for (const v of document.querySelectorAll('.view')) v.hidden = v.id !== `view-${view}`;
  for (const b of document.querySelectorAll('.topbar nav button')) b.classList.toggle('active', b.dataset.view === view);
  window.scrollTo(0, 0);
}
for (const b of document.querySelectorAll('.topbar nav button')) b.addEventListener('click', () => show(b.dataset.view));

// ---------- documents ----------
const fmtSize = (n) => n > 1e6 ? (n / 1e6).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1e3)) + ' kB';
const fmtDate = (t) => new Date(t).toLocaleDateString('nl-NL');

function renderCats() {
  const cats = ['Alles', ...new Set(manifest.docs.map((d) => d.category))];
  const el = $('#cats'); el.innerHTML = '';
  if (cats.length <= 2) return;
  for (const c of cats) {
    const b = document.createElement('button');
    b.textContent = c; b.classList.toggle('active', c === activeCat);
    b.onclick = () => { activeCat = c; renderCats(); renderDocs(); };
    el.append(b);
  }
}

function renderDocs() {
  const q = $('#doc-filter').value.toLowerCase();
  const list = $('#doc-list'); list.innerHTML = '';
  const docs = manifest.docs.filter((d) =>
    (activeCat === 'Alles' || d.category === activeCat) && d.title.toLowerCase().includes(q));
  $('#doc-empty').hidden = manifest.docs.length > 0;
  for (const d of docs) {
    const li = document.createElement('li');
    li.innerHTML = `<span class="name"></span><span class="meta"></span>`;
    li.querySelector('.name').textContent = d.title;
    li.querySelector('.meta').textContent = `${d.category} · ${d.ext.toUpperCase()} · ${fmtSize(d.size)} · ${fmtDate(d.modified)}`;
    li.onclick = () => openDoc(d);
    list.append(li);
  }
}
$('#doc-filter').addEventListener('input', renderDocs);

let viewerToken = 0;
async function openDoc(doc, page = 1) {
  const token = ++viewerToken;
  show('viewer');
  $('#viewer-title').textContent = doc.title;
  const body = $('#viewer-body');
  body.innerHTML = '<p class="muted">Ontsleutelen…</p>';
  const buf = await getFile(doc);
  if (token !== viewerToken) return;
  const url = URL.createObjectURL(new Blob([buf], { type: doc.mime }));
  const dl = $('#download'); dl.href = url; dl.download = doc.name;
  body.innerHTML = '';

  if (doc.ext === 'pdf') {
    const pdf = await pdfjsLib.getDocument({ data: new Uint8Array(buf.slice(0)) }).promise;
    const width = Math.min(body.clientWidth || 800, 1000);
    const canvases = [];
    for (let i = 1; i <= pdf.numPages; i++) {
      const c = document.createElement('canvas'); c.dataset.page = i; body.append(c); canvases.push(c);
    }
    for (let i = 1; i <= pdf.numPages; i++) {
      if (token !== viewerToken) return;
      const p = await pdf.getPage(i);
      const vp1 = p.getViewport({ scale: 1 });
      const scale = (width / vp1.width) * (window.devicePixelRatio || 1);
      const vp = p.getViewport({ scale });
      const c = canvases[i - 1];
      c.width = vp.width; c.height = vp.height; c.style.width = width + 'px';
      await p.render({ canvasContext: c.getContext('2d'), viewport: vp }).promise;
      if (i === page && page > 1) c.scrollIntoView({ block: 'start' });
    }
  } else if (doc.mime.startsWith('image/')) {
    const img = new Image(); img.src = url; img.alt = doc.title; body.append(img);
  } else if (doc.mime.startsWith('text/') || doc.ext === 'json') {
    const pre = document.createElement('pre'); pre.textContent = new TextDecoder().decode(buf); body.append(pre);
  } else {
    body.innerHTML = '<p class="muted">Geen voorbeeld beschikbaar voor dit bestandstype. Gebruik Download.</p>';
  }
}
$('#back').addEventListener('click', () => show('docs'));

// ---------- analyse ----------
const STOP = new Set(`de het een en van in is dat op te voor met zijn niet aan er die als ook om door bij of naar dan maar wordt worden kan nog uit over tot deze dit al wel heeft hebben was zij hij ze we wij je u ik meer geen zo hun haar hem mijn onze uw waar wat wie hoe na toe moet zal zou kunnen werd waren the and of to in is for on that with as by at be this are from or an it was not have has which you we they will can all their its our more also`.split(/\s+/));

$('#run-analyse').addEventListener('click', async () => {
  const pdfs = manifest.docs.filter((d) => d.ext === 'pdf');
  const btn = $('#run-analyse'), prog = $('#analyse-progress'), status = $('#analyse-status');
  btn.disabled = true; prog.hidden = false; prog.max = pdfs.length || 1; prog.value = 0;
  analysis = {};
  for (const [i, d] of pdfs.entries()) {
    status.textContent = `${i + 1}/${pdfs.length}: ${d.title}`;
    try {
      const pdf = await pdfjsLib.getDocument({ data: new Uint8Array((await getFile(d)).slice(0)) }).promise;
      const pages = [];
      for (let p = 1; p <= pdf.numPages; p++) {
        const tc = await (await pdf.getPage(p)).getTextContent();
        pages.push(tc.items.map((it) => it.str).join(' ').replace(/\s+/g, ' '));
      }
      const words = pages.join(' ').match(/[\p{L}\p{N}]+/gu) || [];
      analysis[d.id] = { pages, words };
    } catch (ex) { console.warn(d.title, ex); }
    prog.value = i + 1;
  }
  btn.disabled = false; prog.hidden = true;
  status.textContent = pdfs.length ? `Klaar — ${pdfs.length} PDF's geanalyseerd.` : 'Geen PDF\'s gevonden.';
  renderAnalysis();
});

function renderAnalysis() {
  $('#analyse-results').hidden = false;
  const docs = manifest.docs.filter((d) => analysis[d.id]);
  const nf = new Intl.NumberFormat('nl-NL');
  let pages = 0, words = 0; const freq = new Map();
  const tbody = $('#per-doc'); tbody.innerHTML = '';
  for (const d of docs) {
    const a = analysis[d.id];
    pages += a.pages.length; words += a.words.length;
    for (const w of a.words) {
      const lw = w.toLowerCase();
      if (lw.length < 3 || STOP.has(lw) || /^\d+$/.test(lw)) continue;
      freq.set(lw, (freq.get(lw) || 0) + 1);
    }
    const tr = document.createElement('tr');
    tr.innerHTML = '<td></td><td></td><td></td>';
    tr.children[0].textContent = d.title;
    tr.children[1].textContent = nf.format(a.pages.length);
    tr.children[2].textContent = nf.format(a.words.length);
    tbody.append(tr);
  }
  $('#t-docs').textContent = nf.format(docs.length);
  $('#t-pages').textContent = nf.format(pages);
  $('#t-words').textContent = nf.format(words);
  const terms = $('#terms'); terms.innerHTML = '';
  for (const [w, n] of [...freq].sort((a, b) => b[1] - a[1]).slice(0, 40)) {
    const s = document.createElement('span'); s.textContent = w;
    const b = document.createElement('b'); b.textContent = n; s.append(b); terms.append(s);
  }
  searchText();
}

function searchText() {
  const q = $('#fulltext').value.trim().toLowerCase();
  const hits = $('#hits'); hits.innerHTML = '';
  if (!analysis || q.length < 2) return;
  let count = 0;
  for (const d of manifest.docs) {
    const a = analysis[d.id]; if (!a) continue;
    a.pages.forEach((text, i) => {
      const idx = text.toLowerCase().indexOf(q);
      if (idx < 0 || count >= 100) return;
      count++;
      const start = Math.max(0, idx - 80), end = Math.min(text.length, idx + q.length + 80);
      const li = document.createElement('li');
      const where = document.createElement('div'); where.className = 'where';
      where.textContent = `${d.title} — pagina ${i + 1}`;
      const snip = document.createElement('div');
      const mark = document.createElement('mark'); mark.textContent = text.slice(idx, idx + q.length);
      snip.append((start ? '…' : '') + text.slice(start, idx), mark, text.slice(idx + q.length, end) + (end < text.length ? '…' : ''));
      li.append(where, snip);
      li.onclick = () => openDoc(d, i + 1);
      hits.append(li);
    });
  }
  if (!count) hits.innerHTML = '<li class="muted">Niets gevonden.</li>';
}
$('#fulltext').addEventListener('input', searchText);

// ---------- notes (local only) ----------
function loadNotes() { try { return JSON.parse(localStorage.getItem(NOTES_KEY)) || []; } catch { return []; } }
function saveNotes(n) { try { localStorage.setItem(NOTES_KEY, JSON.stringify(n)); } catch {} }

function renderNotes() {
  const ul = $('#notes'); ul.innerHTML = '';
  for (const [i, n] of loadNotes().entries()) {
    const li = document.createElement('li');
    const p = document.createElement('p'); p.textContent = n.text;
    const sm = document.createElement('small'); sm.textContent = new Date(n.t).toLocaleString('nl-NL'); p.append(sm);
    const del = document.createElement('button'); del.className = 'ghost'; del.textContent = 'Verwijder';
    del.onclick = () => { const all = loadNotes(); all.splice(i, 1); saveNotes(all); renderNotes(); };
    li.append(p, del); ul.append(li);
  }
}
$('#note-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const text = $('#note-text').value.trim(); if (!text) return;
  saveNotes([{ text, t: Date.now() }, ...loadNotes()]);
  $('#note-text').value = ''; renderNotes();
});

resumeSession();
