# TweedeDijk

Private group site on GitHub Pages: https://michtypython.github.io/TweedeDijk/

Tabs: **Documenten** (PDFs with Claude summaries and notes), **To-do**, **Constructie**, **Planning**.

## How the protection works

All data lives in `vault/` and is encrypted (AES-256-GCM) with a key derived from the
username + password. The repo is public, but without the login it only contains unreadable
files. The Claude API key and the GitHub token are stored the same way (`vault/secrets.bin`),
so everybody who can log in can upload and generate summaries.

Commit messages are always just "Update vault", so they never reveal document names.

## One-time setup (in the site: ⚙ Instellingen)

1. **Claude API key**: console.anthropic.com → Billing (add credit) → API keys → Create key.
   This is separate from a claude.ai Pro/Max subscription.
2. **GitHub token**: github.com → Settings → Developer settings → Fine-grained tokens →
   Generate new token. Repository access: *Only select repositories* → `TweedeDijk`.
   Permissions: *Contents: Read and write*.

## Adding documents

Use **+ PDF toevoegen** on the site. For bulk imports from this PC:

1. `git pull` (the website commits too)
2. Put files in `private\` (git-ignored, never uploaded unencrypted)
3. `node tools/encrypt.mjs` and enter the login
4. `git add -A`, `git commit -m "Update vault"`, `git push`

## Testing locally

`python -m http.server 8000` in this folder, then open http://localhost:8000.
