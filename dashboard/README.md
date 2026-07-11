# AgentSSO Dashboard

Interactive visualization of the AgentSSO architecture, token flow, security
properties, components, threat model, and test results.

## Quickstart

```bash
cd dashboard
npm install
npm run dev      # development server at http://localhost:5173
```

## Build for production

```bash
npm run build    # outputs to dist/
npm run preview  # preview the production build
```

## What's inside

The dashboard is a single-page React + TypeScript + TailwindCSS app with:

- **Hero** — project overview with live stats (tests, packages, commits, RFCs)
- **Pillars** — the 5 v0.1 pillars + 2 v2 planned, with status badges
- **Token Flow** — interactive 6-step flow from human login to tool call response
- **Architecture** — ASCII system diagram with trust boundaries and tech stack
- **Components** — filterable grid of all 15 Go packages with test counts + coverage
- **Security Properties** — 8 properties with proof citations from the E2E test
- **AIT Claims** — interactive claim dictionary (RFC 9068 + custom claims)
- **RFC Mapping** — 7 standards with role descriptions
- **Threat Model** — 10 STRIDE threats with severity and mitigation status
- **Test Results** — bar chart of tests per package + E2E test output

## Tech stack

| Layer | Technology |
|---|---|
| Framework | React 19 |
| Language | TypeScript |
| Styling | TailwindCSS 3 |
| Build | Vite 6 |
| Fonts | Inter + JetBrains Mono (Google Fonts) |