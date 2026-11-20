# TweedeDijk

Private document site with a login screen, hosted on GitHub Pages.

Every document is **encrypted in your browser's format (AES-256-GCM)** with a key derived from
username + password. The repo only contains encrypted files (`vault/`); the originals stay on
your PC in `private/` (git-ignored). Without the login, the files are unreadable — even though
the repo is public.

## Adding documents

1. Put files in `C:\TweedeDijk\private\` (subfolders become categories, e.g. `private\Notulen\`).
2. Run: `node tools/encrypt.mjs` and enter the username + password.
3. Publish: `git add -A`, `git commit -m "Documenten bijgewerkt"`, `git push`.

The site updates within a minute or two.

## Testing locally

`python -m http.server 8000` in this folder, then open http://localhost:8000
(opening index.html directly as a file does not work).

## Changing the password

`node tools/encrypt.mjs --reset` re-encrypts everything with new credentials.
