# WebScope Pro

A mobile-first passive Website Intelligence + Security Posture Analyzer.

## Features

- Website overview and HTTP status
- DNS lookup and network timing
- Response-time breakdown
- Security header posture
- Cookie flag observations
- Internal/external/broken/redirect link discovery
- Public resource extraction: scripts, styles, images, fonts, documents
- Video/embed discovery
- OpenGraph and structured-data observations
- Technology fingerprinting from public HTML/headers
- robots.txt and sitemap discovery
- Security/performance/SEO/accessibility-style heuristic scores
- Scan history stored locally
- JSON and standalone HTML report export
- Dark/light responsive UI
- SSRF protections, rate limiting, size/time limits and safe redirects
- No exploit, brute-force, credential attack or destructive scanning

## Requirements

Node.js 20+

## Run

```bash
npm install
npm start
```

Open:

http://localhost:3000

For development:

```bash
npm run dev
```

## Environment

Copy `.env.example` to `.env` if desired. The app also works with defaults.

## Notes

This is a passive analyzer. It only fetches the supplied public HTTP(S) target and parses the response. Link checks are limited to the target's origin and use safe GET requests with bounded concurrency. Private/reserved IP destinations are blocked to reduce SSRF risk.

Some infrastructure and technology detections are heuristic and should be treated as indicators, not proof.
