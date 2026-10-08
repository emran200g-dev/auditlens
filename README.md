# AuditLens

Smart contract audit + GRC mapper. Paste Solidity or a verified contract address and get:

- Findings from **Slither** (static analysis) plus an **AI logic audit**
- Plain-English explanations, business-risk statements, fixes and exploit scenarios
- Controls mapped to **OWASP SC Top 10, ISO 27001 and SOC 2**
- A governance review (owner, admin, multisig or timelock)
- A deterministic **PDF report**, with its SHA-256 anchored **on-chain (Sepolia)**

## Try it (for judges)

- **Live demo:** <REPLACE-WITH-YOUR-VERCEL-URL> (AI-only mode; Slither is not available on Vercel, and the UI shows which engine ran)
- **1-minute path:** open the app, click **Load vulnerable sample**, then **Run audit**. Open a finding to see the exploit scenario, then click **Verify fix by re-scanning**. Use **Ask the audit** to chat about the results.
- **On-chain anchoring** needs MetaMask on Sepolia and a deployed `AuditAttestation` contract (see below). It is optional for a quick evaluation.
- **Slither support:** run locally with Docker (see "Run with Docker").

## Disclosures

- **AI tools:** this project was written with the help of Claude (Anthropic) as a coding assistant. At runtime it calls an LLM through OpenCode Zen (model `space-bunny-free`) for the AI audit, exploit scenarios, fix verification and chat. Pasted contract code is sent to that third-party model. Exploit scenarios and PoCs are model-written and **not executed**.
- **Open source used:** FastAPI, httpx, ReportLab, Slither, solc-select, ethers.js (see the `requirements` files and `frontend/index.html`).
- **Pre-existing work:** none. AuditLens was created on Oct 8, 2026, during the hackathon period.
- **Planning docs:** the Devpost Learn skill pack is installed under `.agents/skills`. `devpost/scope.md`, `devpost/prd.md` and `devpost/spec.md` were written against the pack's templates and reconstructed from the implemented code on Oct 8, 2026, after the build.

## How it works

- **Engines:** Slither (compiler-backed, pragma-matched solc) plus an AI audit for business-logic, accounting and access-control flaws that Slither cannot see. Every AI finding must quote a real source line; citations that don't match the code are dropped.
- **No fake results:** there is no regex fallback. With neither Slither nor an API key, scans fail with a clear error. If Slither can't compile the input, the report says so and runs AI-only.
- **Per finding (AI):** explanation, business risk, fix, exploit scenario, a Foundry PoC (not executed), and control mappings chosen from a fixed catalog. IDs outside the catalog are rejected and replaced by the reference table in `backend/kb.py`.
- **Fix verification:** the model patches the file, the patch is re-scanned, and the result shows whether the finding disappeared and whether new issue types appeared.
- **Governance:** for address scans it reads the chain (`owner()`, EIP-1967 admin) and classifies the holder as EOA, Safe (threshold) or timelock (delay).
- **Anchoring:** MetaMask sends the transaction. The server then checks the Sepolia receipt (mined, success, sent to your contract, calldata hash, `ReportAnchored` event, contract state) before recording it.
- **Chat:** answers use the scan's source and findings.
- **Report:** `backend/report.py` produces a reproducible PDF (same scan = same bytes), hashed once at scan time.

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
cp .env.example .env            # fill in keys, then: set -a; source .env; set +a
cd backend && uvicorn main:app --reload --port 8000
# open http://localhost:8000
```

## Run with Docker (Slither + compilers preinstalled)

```bash
docker build -t auditlens . && docker run --env-file .env -p 8000:8000 auditlens
```

## Deploy on Vercel (AI-only mode)

1. Push the repo to GitHub and import it in Vercel (root directory = repo root, Framework Preset = Other). `app.py`, `requirements.txt` and `vercel.json` are already set up.
2. Under Project Settings > Environment Variables, add `OPENCODE_ZEN_API_KEY` (optional: `AUDITLENS_MODEL`, `CONTRACT_ADDRESS`, `ETHERSCAN_API_KEY`, `RATE_LIMIT_PER_HOUR`). These stay on the server; the browser never sees them.
3. Deploy, then open `/api/config` to confirm the provider and model.

Slither is not installed on Vercel, so scans run AI-only. For Slither, use the Docker image on Fly.io, Railway or Render.

## Deploy the attestation contract (once)

```bash
pip install web3 py-solc-x
PRIVATE_KEY=0x<sepolia key with test ETH> python contracts/deploy.py   # prints CONTRACT_ADDRESS=0x...
```

Add the address to `.env` (or Vercel) and restart. Anchoring signs from the user's MetaMask; verification reads Sepolia directly.

## LLM provider

Set `OPENCODE_ZEN_API_KEY` (OpenAI-compatible endpoint `https://opencode.ai/zen/v1/chat/completions`, model `space-bunny-free`). Test a key first:

```bash
curl https://opencode.ai/zen/v1/chat/completions \
  -H "Authorization: Bearer $OPENCODE_ZEN_API_KEY" \
  -H "content-type: application/json" \
  -d '{"model":"space-bunny-free","messages":[{"role":"user","content":"hi"}]}'
```

Free models can be weaker at strict JSON. Failures degrade to built-in text and never fake results.

## Tests

```bash
python tests/test_e2e.py
```

Exercises every code path against local stub LLM/RPC servers (and the UI via jsdom). It does not prove behavior against the real services.

## Known limits

- Control catalogs are partial, and mappings need review by a GRC owner.
- Multi-file projects with npm-style imports won't compile under Slither from Etherscan source alone.
- PoCs and exploit scenarios are not executed.
- On Vercel, scans are stored in `/tmp` (ephemeral, per instance), so history and PDFs can vanish after a cold start, and the rate limiter is per instance.
- No auth or multi-tenancy; SQLite storage. Use a hosted database for anything beyond a demo.

## License

MIT. See `LICENSE`.
