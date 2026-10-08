---
doc: spec
status: approved
---

# AuditLens — Technical Spec

## How This Works, In Plain Language
A browser app talks to a small Python server. The server runs the analyzers on your contract: Slither (a static analysis tool) when installed, and an AI model that looks for logic bugs Slither cannot see. It scores each finding, maps it to compliance controls, builds a PDF, and stores the result. The browser shows it. For proof, the PDF's hash is sent to a tiny contract on the Sepolia test network through MetaMask, and the server checks the transaction before trusting it. This shape keeps keys on the server and avoids a build step for the front end.

## The Core Journey Through the System
PRD ref: `prd.md > The Core Journey`.
1. User pastes code and clicks **Run audit** → browser POSTs `/api/scan`.
2. Server writes the files to a temp folder, runs Slither, adds an old-compiler pragma check, then the AI audit → raw findings are de-duplicated and scored.
3. The AI step adds explanations, exploits and control picks; the reference table fills any gap → coverage, heatmap and governance are computed.
4. Server builds the PDF, hashes it, saves the scan to SQLite → returns JSON.
5. Browser renders findings and dashboards from that JSON.
6. **Verify fix** → `/api/scans/{id}/findings/{fid}/verify-fix` patches and re-scans.
7. **Anchor** → MetaMask sends `anchor(hash, ref)` → browser posts the tx hash to `/api/scans/{id}/anchor` → server checks the receipt and records it.

## Stack
- Python 3.12, FastAPI, httpx, ReportLab (PDF), SQLite.
- Slither and solc-select for static analysis (Docker image preinstalls compilers 0.4.26 to 0.8.24).
- Vanilla JavaScript front end, ethers.js 6.13.4 for MetaMask.
- Solidity attestation contract on Sepolia.
- LLM through OpenCode Zen (OpenAI-compatible, model `space-bunny-free`).
- Unverified: free models can be weak at strict JSON; failures fall back to built-in text.

## Where It Runs and How Someone Tries It
- Local: `pip install -r backend/requirements.txt`, copy `.env.example` to `.env` and set an LLM key, then `cd backend && uvicorn main:app --port 8000` and open `http://localhost:8000`.
- Docker (with Slither): `docker build -t auditlens . && docker run --env-file .env -p 8000:8000 auditlens`.
- Vercel (AI-only, no Slither) via `app.py` and `vercel.json`.
- Demo recording: Load vulnerable sample → Run audit → open a finding → Verify fix → GRC dashboard → PDF → anchor.
- Submission also needs a public GitHub repo and a demo video; deployment is optional.

## Look and Feel
Carried from `prd.md > Look and Feel`: dark violet palette defined as CSS variables in `frontend/style.css`, Bricolage Grotesque and IBM Plex Mono from Google Fonts, dense cards, severity by colour plus text.

## Components

### Server API (`backend/main.py`)
Routes for config, sample, scan, scan list and detail, PDF download, verify-fix, chat and anchor; per-IP hourly rate limit on LLM routes; serves the front end as static files.
PRD ref: `prd.md > Features and Behavior`.

### Analysis engine (`backend/engine.py`)
Runs Slither, the pragma check and the AI audit, grounds AI citations to real lines, scores risk, builds coverage, heatmap and governance, and implements fix verification and chat.
PRD ref: `prd.md > Scanning`, `prd.md > Fix verification and chat`.

### Knowledge base (`backend/kb.py`)
Fixed frameworks and per-finding-type risk, text, fix and control mappings. Deterministic fallback when the AI is unavailable.
PRD ref: `prd.md > Findings and GRC`.

### Chain helper (`backend/chain.py`)
JSON-RPC reads for owner and proxy admin, holder classification, and anchor receipt verification.
PRD ref: `prd.md > Governance`, `prd.md > Report and attestation`.

### Report builder (`backend/report.py`)
Reproducible PDF of summary, coverage, findings, governance and limitations.
PRD ref: `prd.md > Report and attestation`.

### Front end (`frontend/`)
Hash-routed single page: scan form, findings, GRC, governance, chat, report and history.
PRD ref: `prd.md > Screens and Layout`.

### Attestation contract (`contracts/AuditAttestation.sol`)
`anchor(hash, ref)` stores auditor and timestamp once per hash; `verify(hash)` reads it back.
PRD ref: `prd.md > Report and attestation`.

## Data Model
Table `scans(id, created, name, data JSON, pdf BLOB)`. The JSON holds files, findings, score, counts, coverage, heatmap, governance, engine info, report hash and anchor. Scans persist in SQLite between visits (ephemeral on Vercel). The browser keeps only the current scan in memory.

## File Structure
```
auditlens/
├── backend/        # FastAPI app, engine, kb, chain, report
├── frontend/       # index.html, app.js, style.css
├── contracts/      # AuditAttestation.sol, deploy.py
├── samples/        # VulnerableVault.sol demo input
├── tests/          # end-to-end tests with stub servers
├── devpost/        # scope.md, prd.md, spec.md
├── app.py          # Vercel entrypoint
└── Dockerfile
```

## External Services and Dependencies
- OpenCode Zen `POST https://opencode.ai/zen/v1/chat/completions`: key required, free tier limits apply.
- Etherscan API: optional key to fetch verified source.
- Public RPC endpoints (publicnode) for chain reads and the Sepolia receipt check.
- MetaMask in the browser for signing.

## Important Failure Modes
- **Slither cannot compile the input** → report says so and runs AI-only.
- **LLM call or JSON parse fails** → built-in reference text is shown and the UI says the AI step failed.
- **Anchor transaction not mined yet** → server returns "pending"; the user retries.
- **Rate limit hit** → clear "try again later" message.

## What Was Simplified and Why
- **SQLite in `/tmp`** instead of a hosted database — fastest to demo. The fuller version needs a managed database.
- **Partial control catalogs** instead of complete frameworks — keeps mappings auditable. Completeness needs GRC review.
- **Unexecuted PoCs** instead of sandboxed runs — safety and time.

## Decisions and Open Issues
- No regex fallback when no engine exists — avoids faking results (implementation choice, consistent with `prd.md > Product Decisions`).
- Sepolia only for attestation — test network, no real funds needed.
- Uncertainty to check early: whether the chosen free model returns valid JSON reliably; check by running the sample scan against the real service, since the tests use stubs.
- Open: the deployed demo URL (carried from `prd.md > Open Questions`).
