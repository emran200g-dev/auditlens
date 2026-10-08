---
doc: prd
status: approved
---

# AuditLens — Product Requirements

A web app that audits a Solidity contract and produces a GRC-ready, verifiable report, for security and compliance leads at small Web3 teams.
Source: `scope.md > The Unique Kernel`, `scope.md > Who It's For`.

## The Core Journey
1. The user opens AuditLens and sees **Scan a contract** (`scope.md > The Core Loop`).
2. They paste Solidity, or switch to the address tab and enter a verified contract address, chain and Etherscan key. **Load vulnerable sample** fills in a demo contract.
3. They click **Run audit**. Progress is shown while the engines run.
4. They land on **Findings**: a security score, severity counts and ranked findings. Each finding opens to show the code line, explanation, business risk, fix, exploit scenario and controls.
5. On a finding they click **Verify fix by re-scanning** and see whether it was resolved and whether new issue types appeared.
6. They check the **GRC dashboard** and **Governance check**, and use **Ask the audit** for questions.
7. They open **Report**, download the PDF and, with MetaMask on Sepolia, anchor its SHA-256 hash. Success is a recorded, verifiable attestation.

## Screens and Layout
A left sidebar (New scan, Scan history, and per-scan tabs: Findings, GRC dashboard, Governance check, Ask the audit, Report) plus an engine status panel showing whether Slither and the LLM are active. The main area shows the selected view. Routing is hash-based.

## Look and Feel
Dark theme with a violet accent. Bricolage Grotesque headings, IBM Plex Mono for code and hashes. Dense, dashboard-style cards. Severity is shown by colour and label (Critical, High, Medium, Low). Copy is plain and states limits honestly.

## Features and Behavior

### Scanning
- Paste source (over 30 characters) or fetch verified source by address on a supported chain.
- Slither runs when installed, with a pragma-matched compiler. If it cannot compile, the report says so and runs AI-only.
- An AI logic audit adds business-logic, accounting and access-control findings. Each must quote a real line; citations that do not match the code are dropped.
- With no Slither and no LLM key, the scan fails with a clear error instead of faking results.

### Findings and GRC
- Risk = likelihood × impact, giving Critical, High, Medium or Low. The posture score falls as total risk rises.
- Every finding maps to OWASP SC Top 10, ISO 27001 and SOC 2 controls. AI-selected controls must come from a fixed catalog, otherwise a reference table is used.
- The dashboard shows coverage per framework, failing controls and a likelihood/impact heatmap.

### Governance
- For address scans, reads `owner()` and the EIP-1967 admin and classifies the holder as EOA, Safe (with threshold) or timelock (with delay).
- An AI code review adds governance findings tied to verified lines.

### Fix verification and chat
- The model patches the file, the patch is re-scanned, and the result shows resolved or not, new issue types and a diff.
- Chat answers only from this scan's source and findings, cites finding IDs and says so when something is not covered.

### Report and attestation
- The PDF is reproducible (same scan gives the same bytes) and hashed once at scan time.
- Anchoring is signed by the user's MetaMask. The server then checks the Sepolia receipt (mined, successful, sent to the contract, correct calldata hash, `ReportAnchored` event) before recording it.

- As a compliance lead, I want findings mapped to named controls so that I can attach them to audit evidence.
  - [ ] Every finding shows OWASP, ISO 27001 and SOC 2 control IDs and an owner.
  - [ ] The PDF includes the same mappings.
- As a compliance lead, I want proof the report is unaltered so that I can share it with a third party.
  - [ ] After anchoring, the report shows the transaction and on-chain record.
  - [ ] The recorded hash equals the PDF's SHA-256.

## States and Boundaries
- **First use** — empty scan form with the sample button.
- **No engine available** — scan fails with a message naming what to install or set.
- **AI step fails** — built-in text from the reference table is used; nothing is faked, and the UI notes it.
- **Rate limit** — after the hourly limit the app returns a clear "try later" message.
- **Persistence** — scans and PDFs are stored in SQLite (ephemeral `/tmp` on Vercel). There are no user accounts.
- **Anchoring pending** — if the transaction is not yet mined, the app asks the user to retry.

## Product Decisions
- Fail loudly with no engine rather than fall back to regex — a fake report would damage trust in a compliance tool.
- Control mappings come from a fixed catalog — keeps outputs auditable; the catalog is partial and needs GRC review.
- Hash of the PDF is anchored, not the report text — lets anyone verify the exact file.
- One LLM provider and model (OpenCode Zen, `space-bunny-free`) — keeps the demo runnable on a free model.

## What We're Building
Everything in `scope.md > The POC Boundary`: scanning, findings with explanations and mappings, GRC dashboard, governance check, fix verification, chat, PDF report and Sepolia attestation.

## Deferred From the POC
- Accounts and per-user history — needs auth and a hosted database.
- Multi-file projects with npm imports — Slither cannot resolve them from Etherscan source alone.
- Persistent storage on serverless hosting — the demo accepts ephemeral data.

## Possible Later Enhancements
Run generated PoCs in a sandbox. Expand control catalogs and add more frameworks. Support more attestation chains.

## Non-Goals
- Replacing a manual audit — automated analysis finds known bug classes only.
- Certifying compliance — mappings are guidance for a GRC owner to review.
- Executing exploits — PoCs are model-written and not run.

## Open Questions
- Which hosted URL is the judged demo? Must be answered before submission.
- Should the Vercel demo run AI-only, as it does now? Can wait.
