---
doc: scope
status: approved
---

# AuditLens

A smart contract audit tool that turns a Solidity file or verified address into a security and compliance report a non-engineer can act on.

## The Unique Kernel
Most contract scanners stop at a list of technical findings. AuditLens maps every finding to the controls a GRC team is measured against (OWASP Smart Contract Top 10, ISO 27001, SOC 2), writes a business-risk statement for it, reviews who actually controls the contract (governance), and produces a PDF whose SHA-256 hash can be anchored on-chain so anyone can prove the report was not altered.

## Who It's For
A security or compliance lead at a small DeFi or Web3 team who must show auditors or partners evidence about a contract, but does not read Solidity. Today they get a developer's scanner output, or pay for a manual audit and receive a PDF they cannot verify.

## The Core Loop
1. Open the app and paste Solidity (or enter a verified contract address).
2. Run the audit and open the findings.
3. Read the plain-English explanation and business risk, check the control mapping, and verify a fix by re-scanning.
4. Download the PDF and optionally anchor its hash on Sepolia.

They come back for each new contract or each new version of one.

## Inspiration & Identity
Dark, dense, dashboard feel with a violet accent; Bricolage Grotesque for headings and IBM Plex Mono for code. Credible and plain rather than promotional. Severity uses colour plus a text label.

## Why This Matters to the Learner
To be filled in by the author in their own words.

## What "Working" Looks Like
Load the vulnerable sample, run the audit, and see ranked findings with explanations, a GRC coverage dashboard, a governance check, and a downloadable PDF. The "oh, that's cool" beat: click **Verify fix by re-scanning** on a finding and see the AI-written patch re-scanned and the finding disappear, then anchor the PDF hash on-chain.

## The POC Boundary
In:
- Paste Solidity or fetch verified source by address.
- Slither static analysis when installed, plus an AI logic audit; findings must cite real source lines.
- Per-finding explanation, business risk, fix and control mapping from a fixed catalog.
- GRC coverage dashboard and risk heatmap.
- Governance check for address scans (owner, proxy admin, EOA vs Safe vs timelock).
- Fix verification by re-scan.
- Chat about one audit.
- Reproducible PDF report and Sepolia hash attestation.

## Later
- Multi-file projects with npm-style imports.
- Hosted database and user accounts.
- Executing the generated Foundry PoCs.
- Fuller control catalogs reviewed by a GRC owner.

## Explicitly Cut
- Regex-based fallback scanner: it would fake results when no engine is available, so scans fail with a clear error instead.
- Auth and multi-tenancy: not needed to prove the kernel and the core loop.
- Running exploit PoCs: unsafe and out of scope for a proof of concept.
