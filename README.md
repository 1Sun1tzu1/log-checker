# 🕵️ Log Checker – The Art of D3fense

A lightweight, browser-only log analyzer. Upload server logs (Apache/Nginx combined format, SSH auth logs, etc.) or paste them into the textarea and get instant anomaly detection. Useful for demos, workshops, or a quick triage.

## Features
- Detects repeated failed logins (brute-force attempts)
- Flags HTTP error spikes (403, 404, 500, 502, 503)
- Highlights suspicious user-agents (curl, wget, Postman, python-requests, sqlmap, etc.)
- Notes off-hours activity (00:00–05:00) and request rate spikes (>120 req/min)
- Runs entirely in the browser — logs never leave the machine

## Quick Start
```bash
npm install
npm run dev
```

## Build
```bash
npm run build
```

## Deploy to GitHub Pages
- Keep `base: '/log-checker/'` in `vite.config.ts` for project pages.
- Enable GitHub Actions → Pages in repo settings.

## Add Your Own Rules
Edit `src/parsers.ts` to tweak regexes or thresholds and add new anomaly rules.
