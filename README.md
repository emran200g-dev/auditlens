# AuditLens

Smart contract audit + GRC mapper. Paste Solidity or a verified address, get findings from Slither, plain-English
explanations and business-risk statements from an LLM, controls mapped to OWASP SC Top 10 / ISO 27001 / SOC 2,
a governance review, a deterministic PDF report, and an on-chain attestation of that PDF's SHA-256 on Sepolia.

## Try it (for judges)
- **Live demo:** <REPLACE-WITH-YOUR-VERCEL-URL> (runs AI-only; Slither is not available on Vercel, and the UI says which engine ran).
- **Fastest path (1 minute):** open the app, click **Load vulnerable sample**, then **Run audit**. Open a finding to see the exploit scenario, then **Verify fix by re-scanning**. Use **Ask the audit** to chat about the results.
- **On-chain anchoring** needs MetaMask on Sepolia and a deployed `AuditAttestation` contract (see below), so it is optional for a quick evaluation.
- **Local run:** see "Run" below, or `docker build -t auditlens . && docker run --env-file .env -p 8000:8000 auditlens` for Slither support. Set `OPENCODE_ZEN_API_KEY` in `.env`.
- **Tests:** `python tests/test_e2e.py` (uses local stub servers for the LLM and RPC; it does not prove behavior against the real services).

## Disclosures
- **AI tools:** this project was written with the help of Claude (Anthropic) as a coding assistant. At runtime it calls an LLM through OpenCode Zen (model `space-bunny-free`) for the AI audit, exploit scenarios, fix verification and chat. Pasted contract code is sent to that third-party model. Exploit scenarios and PoCs are model-written and not executed.
- **Open source used:** FastAPI, httpx, ReportLab, Slither, solc-select, ethers.js (see `requirements` files and `index.html`).
- **Pre-existing work:** none declared. <CONFIRM: remove this line or describe any earlier version of AuditLens that existed before Sept 22, 2026.>
- **Planning docs:** the Devpost Learn skill pack is installed under `.agents/skills`; `devpost/scope.md`, `devpost/prd.md` and `devpost/spec.md` were written against the pack's templates and reconstructed from the implemented code on Oct 8, 2026, after the build.

## Run
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
cp .env.example .env            # fill in keys, then: set -a; source .env; set +a
cd backend && uvicorn main:app --reload --port 8000
# open http://localhost:8000
```
## Deploy the attestation contract (once)
```bash
pip install web3 py-solc-x
PRIVATE_KEY=0x<sepolia key with test ETH> python contracts/deploy.py   # prints CONTRACT_ADDRESS=0x...
```
Add the address to `.env` and restart. Anchoring signs from the user's MetaMask; verification reads Sepolia directly.

## Run with Docker (recommended: Slither + compilers preinstalled)
```bash
docker build -t auditlens . && docker run --env-file .env -p 8000:8000 auditlens
```

## Deploy on Vercel (AI-only mode)
1. Push the repo to GitHub, import it in Vercel (root directory = repo root; `app.py`, `requirements.txt` and `vercel.json` are already set up).
2. Project Settings > Environment Variables: `OPENCODE_ZEN_API_KEY` (and optionally `AUDITLENS_MODEL`, `CONTRACT_ADDRESS`, `ETHERSCAN_API_KEY`, `RATE_LIMIT_PER_HOUR`). These live only on the server; the browser never sees them.
3. Deploy. Slither is not installed on Vercel, so scans run AI-only and the UI says so. For Slither use the Docker image on Fly.io/Railway/Render.
Limits: scans are stored in `/tmp` (ephemeral, per instance), so history and PDFs can vanish after a cold start; the rate limiter is also per instance. Use a hosted database for anything beyond a demo.

## LLM provider
Set `OPENCODE_ZEN_API_KEY` (OpenAI-compatible, `https://opencode.ai/zen/v1/chat/completions`, model `space-bunny-free`). Check your key first:
`curl https://opencode.ai/zen/v1/chat/completions -H "Authorization: Bearer $OPENCODE_ZEN_API_KEY" -H "content-type: application/json" -d '{"model":"space-bunny-free","messages":[{"role":"user","content":"hi"}]}'`
Free models can be weaker at strict JSON; failures degrade to built-in text, they never fake results.

## How it works
- **Engines:** Slither (compiler-backed static analysis, pragma-matched solc) plus an AI logic audit that looks for business-logic, accounting and access-control flaws Slither cannot see. Every AI finding must quote a real source line; citations that don't match the code are dropped. There is **no regex fallback**: with neither Slither nor `OPENCODE_ZEN_API_KEY`, scans fail with a clear error rather than faking results. If Slither can't compile the input, the report says so and runs AI-only.
- **Per finding (AI):** plain-English explanation, business risk, fix, exploit scenario and a Foundry PoC (written by the model, **not executed**), and control mappings chosen from a fixed catalog (IDs outside the catalog are rejected, falling back to the reference table in `kb.py`).
- **Fix verification:** the model patches the file, the patch is re-scanned (Slither when available, plus the AI audit), and the result shows whether that finding disappeared and whether new issue types appeared.
- **Governance:** for address scans it reads the chain: `owner()`, EIP-1967 admin, then classifies the holder as EOA, Safe (threshold) or timelock (delay). The AI review adds code-level findings tied to verified lines.
- **Anchoring:** MetaMask sends the tx; the server then checks the Sepolia receipt (mined, success, sent to your contract, calldata hash, `ReportAnchored` event, and contract state) before recording it.
- **Chat:** ask questions about the audit; answers use the scan's source and findings.
- `report.py`: reproducible PDF (same scan = same bytes), hashed once at scan time.

## Known limits
Control catalogs are partial lists and mappings need review by a GRC owner. Multi-file projects with npm-style imports won't compile under Slither from Etherscan source alone. PoCs and exploit scenarios are unexecuted. No auth/multi-tenancy; SQLite storage.

## Tests
`tests/test_e2e.py` exercises every code path against local stub LLM/RPC servers (and the UI via jsdom). It does not prove behavior against the real services.
