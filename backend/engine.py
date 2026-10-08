"""Analysis pipeline: Slither (compiler-backed static analysis) + AI logic audit -> grounded enrichment -> on-chain + AI governance -> scoring."""
import json, os, re, shutil, subprocess, tempfile, hashlib
from pathlib import Path
import httpx
from kb import KB, SLITHER_MAP, FRAMEWORKS, severity
import chain
import difflib
from concurrent.futures import ThreadPoolExecutor

MINOR = {"0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12", "0.7": "0.7.6", "0.8": "0.8.24"}
sha256 = lambda b: hashlib.sha256(b if isinstance(b, bytes) else b.encode()).hexdigest()

def solc_version(src):
    m = re.search(r"pragma\s+solidity\s+[\^>=<~ ]*(\d+\.\d+(?:\.\d+)?)", src)
    if not m: return None
    v = m.group(1)
    return v if v.count(".") == 2 else MINOR.get(v)

def body(L, i):
    depth, out = 0, []
    for l in L[i:i + 40]:
        out.append(l); depth += l.count("{") - l.count("}")
        if depth <= 0 and "{" in "".join(out): break
    return "\n".join(out)


class NoEngine(RuntimeError): pass

# ---------- LLM (OpenCode Zen, model space-bunny-free) ----------
ZEN = "https://opencode.ai/zen/v1"
def provider(): return "zen" if os.getenv("OPENCODE_ZEN_API_KEY") else None
def llm_on(): return provider() is not None
MODEL = lambda: os.getenv("AUDITLENS_MODEL") or "space-bunny-free"

def claude(user=None, system=None, max_tokens=4000, messages=None):
    """One LLM call. Provider is chosen by which key is set; keys never leave the server."""
    pv = provider(); msgs = messages or [{"role": "user", "content": user}]
    if not pv: raise NoEngine("No LLM key set (OPENCODE_ZEN_API_KEY).")
    if pv == "zen":
        r = httpx.post(os.getenv("ZEN_BASE_URL", ZEN) + "/chat/completions", timeout=170, headers={"Authorization": "Bearer " + os.environ["OPENCODE_ZEN_API_KEY"], "content-type": "application/json"},
                       json={"model": MODEL(), "max_tokens": max_tokens, "messages": ([{"role": "system", "content": system}] if system else []) + msgs})
        if r.status_code >= 400: raise RuntimeError(f"OpenCode Zen API {r.status_code}: {r.text[:200]}")
        return re.sub(r"<think>.*?</think>", "", r.json()["choices"][0]["message"].get("content") or "", flags=re.S).strip()

def jparse(t):
    t = re.sub(r"<think>.*?</think>", "", t, flags=re.S).strip(); t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t)
    m = re.search(r"[\[{]", t)
    return json.JSONDecoder().raw_decode(t[m.start():])[0] if m else None   # tolerant of trailing prose

def numbered(files, limit=24000):
    return "\n\n".join(f"// FILE {p}\n" + "\n".join(f"{i + 1}: {l}" for i, l in enumerate(s.split("\n"))) for p, s in files.items())[:limit]

norm = lambda x: re.sub(r"\s+", "", x)
def ground(files, p, line, snippet, window=8):
    """Return the real 1-based line where `snippet` occurs near `line`, else None. Rejects hallucinated citations."""
    if p not in files or not snippet or not norm(snippet): return None
    L = files[p].split("\n"); n = norm(snippet.split("\n")[0])
    for d in sorted(range(-window, window + 1), key=abs):
        i = (line or 1) - 1 + d
        if 0 <= i < len(L) and n and n in norm(L[i]): return i + 1
    return None

def d_oldsolc(L):
    src = "\n".join(L)
    for i, l in enumerate(L):
        m = re.search(r"pragma\s+solidity\s+[\^>=<~ ]*(\d+)\.(\d+)", l)
        if m: return [i] if int(m[1]) == 0 and int(m[2]) < 8 and "SafeMath" not in src else []
    return []

def run_slither(work: Path, target: Path, src: str):
    exe = shutil.which("slither")
    if not exe: return None, "Slither is not installed on this server."
    env = os.environ.copy(); v = solc_version(src)
    if v and shutil.which("solc-select"):
        subprocess.run(["solc-select", "install", v], capture_output=True, timeout=180)
        env["SOLC_VERSION"] = v
    out = work / "slither.json"
    try:
        p = subprocess.run([exe, str(target), "--json", str(out)], capture_output=True, text=True, timeout=240, env=env, cwd=work)
    except subprocess.TimeoutExpired:
        return None, "Slither timed out."
    if not out.exists(): return None, "Slither failed (" + (p.stderr.strip().splitlines() or ["unknown"])[-1][:160] + ")."
    j = json.loads(out.read_text())
    if not j.get("success") and not (j.get("results") or {}).get("detectors"):
        return None, "Slither could not compile the source (" + str(j.get("error"))[:160] + ")."
    return j["results"]["detectors"], None


def fetch_verified(address, chain_id, key):
    r = httpx.get("https://api.etherscan.io/v2/api", params={"chainid": chain_id, "module": "contract", "action": "getsourcecode", "address": address, "apikey": key}, timeout=30).json()
    res = r.get("result")
    if not isinstance(res, list) or not res or not res[0].get("SourceCode"):
        raise ValueError("No verified source for that address: " + str(res)[:160])
    s, name = res[0]["SourceCode"], res[0].get("ContractName", "Contract")
    if s.startswith("{"):
        o = json.loads(s[1:-1] if s.startswith("{{") else s)
        return {p: f["content"] for p, f in (o.get("sources") or o).items()}, name
    return {f"{name}.sol": s}, name


# ---------- AI logic audit ----------
def llm_audit(files, known):
    """Second pair of eyes: business-logic, economic and access-control flaws that static analyzers cannot see. Every claim must quote real code."""
    prompt = ("You are a senior smart-contract auditor. Find LOGIC, ACCESS-CONTROL, ACCOUNTING and ECONOMIC vulnerabilities that static analyzers like Slither miss. "
              "Only report issues you can point to in the code; do not repeat the already-found list; do not report style or gas. "
              'Return JSON only: [{"title":"","file":"","line":0,"snippet":"exact single line copied from the code","likelihood":1-5,"impact":1-5,"explanation":"2-3 sentences"}]. Empty list if none.\n\n'
              f"ALREADY FOUND: {json.dumps(known)}\n\nSOURCE (line-numbered):\n{numbered(files)}")
    out = []
    for x in jparse(claude(prompt, max_tokens=4000)) or []:
        ln = ground(files, x.get("file") or next(iter(files)), int(x.get("line") or 1), x.get("snippet", ""))
        if ln is None: continue   # not grounded in the real source: dropped
        out.append(dict(title=str(x["title"])[:120], file=x.get("file") or next(iter(files)), line=ln, L=min(5, max(1, int(x.get("likelihood", 3)))), I=min(5, max(1, int(x.get("impact", 3)))), expl=str(x.get("explanation", ""))))
    return out

# ---------- Enrichment: explanation, exploit, PoC, grounded control mapping ----------
CATALOG = {k: fw["controls"] for k, fw in FRAMEWORKS.items()}
def llm_enrich(findings, files):
    if not llm_on() or not findings: return False, None
    def chunk_job(chunk):
        items = [{"id": f["id"], "title": f["title"], "file": f["file"], "line": f["line"], "code": f["code"], "analyzer_note": f["analyzer_note"][:400]} for f in chunk]
        prompt = ("You are a smart-contract auditor writing for a GRC audience. For each finding return JSON only: "
                  '[{"id":"F1","explanation":"2-3 plain sentences","risk_statement":"1 sentence business/compliance impact","fix":"short description","fix_code":"Solidity snippet",'
                  '"exploit":["step 1","step 2","..."],"poc":"Foundry test (Solidity) that demonstrates the exploit, or empty if not applicable","owasp":"one id from the catalog","iso":["ids from catalog"],"soc2":["ids from catalog"]}]. '
                  f"Control ids MUST be copied exactly from this catalog: {json.dumps(CATALOG)}. No prose, no fences.\n\nFINDINGS:\n{json.dumps(items)}\n\nSOURCE:\n{numbered(files, 16000)}")
        try: by = {x["id"]: x for x in jparse(claude(prompt, max_tokens=7000))}
        except Exception as e: return 0, f"AI enrichment failed for some findings ({type(e).__name__}); built-in text shown."
        n = 0
        for f in chunk:
            x = by.get(f["id"])
            if not x: continue
            f["explanation"] = x.get("explanation") or f["explanation"]; f["risk_statement"] = x.get("risk_statement", ""); f["fix"] = x.get("fix") or f["fix"]; f["fix_code"] = x.get("fix_code") or f["fix_code"]
            ex = x.get("exploit"); f["exploit"] = ex if isinstance(ex, list) else ([ex] if ex else []); f["poc"] = x.get("poc") or ""
            o = x.get("owasp"); i = [c for c in x.get("iso") or [] if c in CATALOG["iso"]]; s = [c for c in x.get("soc2") or [] if c in CATALOG["soc2"]]
            if o in CATALOG["owasp"] and i and s: f["owasp"], f["iso"], f["soc2"], f["mapping"] = o, i, s, "ai-selected from catalog"
            f["ai"] = True; n += 1
        return n, None
    with ThreadPoolExecutor(4) as ex: res = list(ex.map(chunk_job, [findings[k:k + 5] for k in range(0, len(findings), 5)]))
    done, errs = sum(r[0] for r in res), [r[1] for r in res if r[1]]
    return done > 0, (MODEL() if done else (errs[0] if errs else None))

# ---------- Governance ----------
def governance(files, address, chain_id):
    items, notes = [], []
    if address:
        ev, note = chain.governance_evidence(address, chain_id)
        for e in ev: e["source"] = "on-chain"; items.append(e)
        if note: notes.append(note)
    if llm_on():
        facts = [i["title"] for i in items]
        prompt = ("Review this contract for GOVERNANCE and CENTRALIZATION risk: privileged roles, upgradeability, pause powers, minting, parameter/oracle control, missing timelocks, unsafe ownership transfer. "
                  f"On-chain facts already established: {json.dumps(facts)}. "
                  'Return JSON only: [{"severity":"High|Medium|Low","title":"","file":"","line":0,"snippet":"exact line from code proving it","why":"","fix":""}]. Empty list if none.\n\n' + numbered(files))
        try:
            for x in jparse(claude(prompt, max_tokens=3000)) or []:
                f = x.get("file") or next(iter(files)); ln = ground(files, f, int(x.get("line") or 1), x.get("snippet", ""))
                if ln and x.get("severity") in ("High", "Medium", "Low"):
                    items.append(dict(severity=x["severity"], title=str(x["title"])[:140], why=x.get("why", ""), fix=x.get("fix", ""), detail=[f"{f}:{ln}  {files[f].split(chr(10))[ln - 1].strip()}"], source="ai-review"))
        except Exception as e: notes.append(f"AI governance review failed ({type(e).__name__}).")
    else: notes.append("AI governance review is off (no LLM key set).")
    if not address: notes.append("No address given, so on-chain owner/timelock checks were not possible.")
    score = None if not items and (not llm_on() and not address) else max(0, 100 - sum({"High": 35, "Medium": 15, "Low": 5}[i["severity"]] for i in items))
    return {"score": score, "items": items, "notes": notes}

# ---------- Orchestrator ----------
def analyze(files: dict, main_name: str, ctx_name: str, address=None, chain_id=1, light=False):
    work = Path(tempfile.mkdtemp(prefix="auditlens-"))
    try:
        for p, s in files.items():
            t = work / p; t.parent.mkdir(parents=True, exist_ok=True); t.write_text(s)
        target = next((work / p for p, s in files.items() if re.search(rf"\bcontract\s+{re.escape(ctx_name)}\b", s)), work / next(iter(files)))
        det, note = run_slither(work, target, target.read_text())
        if det is None and not llm_on():
            raise NoEngine((note or "Slither unavailable.") + " No analysis engine is available: install Slither + solc (see README / Dockerfile) or set an LLM key (OPENCODE_ZEN_API_KEY).")
        raw = []  # (key, file, line, check, impact, confidence, note, L, I, title, expl, engine)
        for d in det or []:
            if d.get("impact") in ("Informational", "Optimization"): continue
            el = next((e for e in d["elements"] if e.get("source_mapping", {}).get("lines")), None)
            if not el: continue
            sm = el["source_mapping"]
            raw.append((SLITHER_MAP.get(d["check"], "generic"), sm.get("filename_relative", target.name), sm["lines"][0], d["check"], d["impact"], d["confidence"], d["description"].strip(), None, None, None, None, "slither"))
        for p, s in files.items():
            for i in d_oldsolc(s.split("\n")): raw.append(("old-solc", p, i + 1, "pragma", None, None, "Compiler pragma < 0.8 and no SafeMath", None, None, None, None, "pragma"))
        llm_note = None
        if llm_on():
            try:
                for a in llm_audit(files, [{"title": r[3], "file": r[1], "line": r[2]} for r in raw]):
                    raw.append(("logic", a["file"], a["line"], "ai-logic", None, None, "AI audit finding", a["L"], a["I"], a["title"], a["expl"], "ai-audit"))
            except Exception as e: llm_note = f"AI logic audit failed ({type(e).__name__}: {str(e)[:100]})."
        seen, findings = set(), []
        for key, p, line, check, imp, conf, nt, aL, aI, title, expl, eng in sorted(raw, key=lambda r: (r[1], r[2])):
            if (key, p, line) in seen: continue
            seen.add((key, p, line)); kb = KB[key]; Lines = files[p].split("\n") if p in files else []
            Lk = aL or ({"High": 4, "Medium": 3, "Low": 2}.get(conf, kb["L"]) if conf else kb["L"]); Ik = aI or ({"High": 5, "Medium": 3, "Low": 2}.get(imp, kb["I"]) if key == "generic" else kb["I"])
            risk = Lk * Ik
            findings.append(dict(check=check, key=key, title=title or (kb["t"] if key != "generic" else f"Analyzer: {check}"), file=p, line=line, code=(Lines[line - 1].strip() if 0 < line <= len(Lines) else ""),
                severity=severity(risk), likelihood=Lk, impact=Ik, risk=risk, engine=eng, analyzer_note=nt, owasp=kb["o"], iso=kb["i"], soc2=kb["s"], owner=kb["own"], mapping="reference table (review by GRC owner)",
                explanation=expl or kb["x"], risk_statement="", fix=kb["f"], fix_code=kb["c"], exploit=[], poc="", ai=False))
        findings.sort(key=lambda f: (-f["risk"], f["file"], f["line"]))
        for n, f in enumerate(findings, 1): f["id"] = f"F{n}"
        llm_ok, llm_info = (False, None) if light else llm_enrich(findings, files)
        for f in findings:
            if not f["risk_statement"]: f["risk_statement"] = f"Maps to {f['owasp']}; unresolved, it is a gap against {', '.join(f['iso'] + f['soc2'])}."
        cov = {}
        for k, fw in FRAMEWORKS.items():
            hit = {f["owasp"] for f in findings} if k == "owasp" else {c for f in findings for c in (f["iso"] if k == "iso" else f["soc2"])}
            bad = [c for c in fw["controls"] if c in hit]
            cov[k] = dict(name=fw["name"], pct=round(100 * (len(fw["controls"]) - len(bad)) / len(fw["controls"])), failing=bad, total=len(fw["controls"]))
        cells = {}
        for f in findings: cells.setdefault((f["likelihood"], f["impact"]), []).append(f["id"])
        counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("Critical", "High", "Medium", "Low")}
        return dict(name=ctx_name, address=address, chain_id=chain_id, source_sha256=sha256("".join(files[k] for k in sorted(files))), files=files, loc=sum(s.count("\n") + 1 for s in files.values()),
            engine=dict(slither=det is not None, note=" ".join(x for x in (note, llm_note) if x) or None, llm=llm_ok, llm_info=llm_info, ai_audit=llm_on() and not llm_note),
            score=round(100 / (1 + sum(f["risk"] for f in findings) / 40)), counts=counts, findings=findings,
            heatmap=[dict(l=l, i=i, ids=ids) for (l, i), ids in cells.items()], coverage=cov, governance=None if light else governance(files, address, chain_id))
    finally:
        shutil.rmtree(work, ignore_errors=True)

# ---------- Fix verification: patch, then re-scan the patched code ----------
def verify_fix(scan, fid):
    f = next((x for x in scan["findings"] if x["id"] == fid), None)
    if not f: raise ValueError("Unknown finding.")
    if not llm_on(): raise NoEngine("Fix verification needs an LLM key to write the patch.")
    files, p = scan["files"], f["file"]
    t = claude(f"Return ONLY the complete corrected Solidity source of this file (no fences, no commentary). Make the minimal change that fixes ONLY this vulnerability and keeps everything else identical.\n\n"
               f"VULNERABILITY: {f['title']} at {p}:{f['line']}: {f['code']}\nDETAIL: {f['explanation']}\n\nFILE {p}:\n{files[p]}", max_tokens=8000)
    patched = re.sub(r"^```\w*\s*|\s*```$", "", t.strip())
    if "pragma" not in patched: raise RuntimeError("The model did not return a Solidity file.")
    r = analyze({**files, p: patched}, p, scan["name"], light=True)
    key = f["key"]; bk = lambda fs, k: [x for x in fs if x["key"] == k]
    if key == "logic":
        remaining = bk(r["findings"], "logic")
        j = jparse(claude('Does the patched code still contain this vulnerability? Answer JSON only: {"still_present":true|false,"reason":"one sentence"}\n\n'
                          f"ORIGINAL FINDING: {f['title']} - {f['explanation']}\n\nPATCHED FILE:\n{numbered({p: patched})}\n\nAUDITOR'S FINDINGS ON PATCHED CODE: {json.dumps([x['title'] for x in remaining])}", max_tokens=400))
        resolved, reason = not j["still_present"], j["reason"]
    else:
        n0, n1 = len(bk(scan["findings"], key)), len(bk(r["findings"], key)); resolved = n1 < n0
        reason = f"{key} findings dropped from {n0} to {n1}." if resolved else f"{n1} finding(s) of this type remain after the patch."
    reg = [k for k in {x["key"] for x in r["findings"]} - {key} if len(bk(r["findings"], k)) > len(bk(scan["findings"], k))]
    diff = "".join(difflib.unified_diff(files[p].splitlines(True), patched.splitlines(True), f"a/{p}", f"b/{p}"))
    return dict(finding=fid, resolved=resolved, reason=reason, new_issue_types=reg, diff=diff, patched=patched, rescan_engine=("Slither re-scan" if r["engine"]["slither"] else "AI re-audit only (Slither not available)") + (" + AI audit" if r["engine"]["ai_audit"] and r["engine"]["slither"] else ""),
                note=r["engine"]["note"], remaining=len(r["findings"]), before=len(scan["findings"]))

# ---------- Chat with the audit ----------
def chat(scan, msgs):
    ctx = json.dumps([{k: f[k] for k in ("id", "title", "severity", "file", "line", "code", "explanation", "fix")} for f in scan["findings"]])
    system = ("You are AuditLens' audit assistant. Answer questions about THIS contract and THIS audit only, using the findings and source below. Cite finding ids (F1...) and line numbers from the source. "
              "If something is not in the audit or source, say so instead of guessing. Be concise.\n\n"
              f"FINDINGS: {ctx}\n\nGOVERNANCE: {json.dumps((scan.get('governance') or {}).get('items', []))[:3000]}\n\nSOURCE:\n{numbered(scan['files'], 20000)}")
    clean = [{"role": m["role"], "content": str(m["content"])[:4000]} for m in msgs[-12:] if m.get("role") in ("user", "assistant") and m.get("content")]
    if not clean or clean[-1]["role"] != "user": raise ValueError("Send a user message.")
    return claude(system=system, messages=clean, max_tokens=1200)
