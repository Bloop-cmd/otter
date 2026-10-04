# Otti — Demo Website

A GitHub-ready static demo for the Otti private messenger + Codex concept.

## Included

- Gen-Z friendly animated visual system
- Original cute collectible-toy-inspired otter mascot (not a copy of any existing character)
- One-tap **DIVE** privacy mode
- Ancient-glyph DIVE transition
- Peek-protection camera permission flow
- Simulated peek trigger for testing
- Chats
- Groups
- Status
- Otti Codex
- Gen-Z slang → symbol library
- Responsive mobile bottom navigation
- No inappropriate water-drop icon; DIVE uses `⌁` / `〰` visual language

## Run locally

Open `index.html` in a browser, or use a local server:

```bash
python3 -m http.server 8080
```

Then visit `http://localhost:8080`.

Camera access generally requires `localhost` or HTTPS.

## GitHub Pages

1. Create a repository.
2. Upload `index.html`, `styles.css`, and `app.js`.
3. In GitHub: Settings → Pages → Deploy from branch → `main` / root.
4. Open the generated Pages URL.

## Production notes

The demo intentionally uses a simulated peek trigger. For production, replace it with an on-device face/pose detector and keep camera frames local. Add explicit permission controls, sensitivity settings, a clear camera indicator, and robust false-positive handling.
