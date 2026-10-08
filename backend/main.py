import json, os, shutil, sqlite3, time, uuid
from pathlib import Path
from collections import defaultdict, deque
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import engine, report, chain

ROOT = Path(__file__).resolve().parent.parent
DB = os.getenv("AUDITLENS_DB", "/tmp/auditlens.db" if os.getenv("VERCEL") else str(ROOT / "data.db"))   # Vercel: only /tmp is writable (ephemeral)
app = FastAPI(title="AuditLens")

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, created REAL, name TEXT, data TEXT, pdf BLOB)")
    return c

HITS = defaultdict(deque)
def limit(req: Request):
    """Protects your LLM key/credits from abuse. In-memory, per server instance."""
    ip = (req.headers.get("x-forwarded-for") or req.client.host or "?").split(",")[0].strip(); q = HITS[ip]; now = time.time()
    while q and now - q[0] > 3600: q.popleft()
    if len(q) >= int(os.getenv("RATE_LIMIT_PER_HOUR", "20")): raise HTTPException(429, "Rate limit reached for this demo. Try again later.")
    q.append(now)

class ScanReq(BaseModel):
    source: str | None = None
    address: str | None = None
    chain_id: int = 1
    etherscan_key: str | None = None

class AnchorReq(BaseModel):
    tx: str

class ChatReq(BaseModel):
    messages: list[dict]

@app.get("/api/config")
def config():
    return dict(slither=bool(shutil.which("slither")), llm=engine.llm_on(), model=engine.MODEL(), provider=engine.provider(),
                contract=os.getenv("CONTRACT_ADDRESS") or None, chain_id=11155111, rpc=os.getenv("SEPOLIA_RPC", "https://ethereum-sepolia-rpc.publicnode.com"))

@app.get("/api/sample")
def sample(): return {"source": (ROOT / "samples" / "VulnerableVault.sol").read_text()}

@app.post("/api/scan", dependencies=[Depends(limit)])
def scan(req: ScanReq):
    try:
        if req.address:
            key = req.etherscan_key or os.getenv("ETHERSCAN_API_KEY")
            if not key: raise ValueError("An Etherscan API key is required to fetch source by address.")
            files, name = engine.fetch_verified(req.address.strip(), req.chain_id, key)
        elif req.source and len(req.source.strip()) > 30:
            import re
            files = {"Contract.sol": req.source}; m = re.search(r"\bcontract\s+(\w+)", req.source); name = m[1] if m else "Contract"
        else:
            raise ValueError("Paste Solidity source or enter a verified contract address.")
        result = engine.analyze(files, next(iter(files)), name, address=req.address.strip() if req.address else None, chain_id=req.chain_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except engine.NoEngine as e:
        raise HTTPException(503, str(e))
    result.update(id=uuid.uuid4().hex[:10], created=time.time(), anchor=None)
    pdf = report.build_pdf(result); result["report_sha256"] = engine.sha256(pdf)
    with db() as c: c.execute("INSERT INTO scans VALUES(?,?,?,?,?)", (result["id"], result["created"], name, json.dumps(result), pdf))
    return result

def load(i):
    with db() as c: r = c.execute("SELECT * FROM scans WHERE id=?", (i,)).fetchone()
    if not r: raise HTTPException(404, "Scan not found")
    return r

@app.get("/api/scans")
def scans():
    with db() as c: rows = c.execute("SELECT data FROM scans ORDER BY created DESC LIMIT 100").fetchall()
    out = []
    for r in rows:
        d = json.loads(r["data"]); out.append({k: d[k] for k in ("id", "name", "created", "score", "counts", "report_sha256", "anchor")})
    return out

@app.get("/api/scans/{i}")
def get_scan(i: str): return json.loads(load(i)["data"])

@app.get("/api/scans/{i}/report.pdf")
def pdf(i: str):
    return Response(load(i)["pdf"], media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="auditlens-{i}.pdf"'})

@app.post("/api/scans/{i}/findings/{fid}/verify-fix", dependencies=[Depends(limit)])
def verify_fix(i: str, fid: str):
    try: return engine.verify_fix(json.loads(load(i)["data"]), fid)
    except ValueError as e: raise HTTPException(400, str(e))
    except engine.NoEngine as e: raise HTTPException(503, str(e))
    except RuntimeError as e: raise HTTPException(502, str(e))

@app.post("/api/scans/{i}/chat", dependencies=[Depends(limit)])
def chat_ep(i: str, req: ChatReq):
    try: return {"reply": engine.chat(json.loads(load(i)["data"]), req.messages)}
    except ValueError as e: raise HTTPException(400, str(e))
    except engine.NoEngine as e: raise HTTPException(503, str(e))
    except RuntimeError as e: raise HTTPException(502, str(e))

@app.post("/api/scans/{i}/anchor")
def anchored(i: str, req: AnchorReq):
    r = load(i); d = json.loads(r["data"]); c = os.getenv("CONTRACT_ADDRESS")
    if not c: raise HTTPException(400, "CONTRACT_ADDRESS is not configured.")
    if d.get("anchor"): return d["anchor"]
    try: d["anchor"] = chain.verify_anchor(11155111, req.tx.strip(), d["report_sha256"], c)
    except chain.Pending as e: raise HTTPException(409, str(e))
    except ValueError as e: raise HTTPException(400, str(e))
    except RuntimeError as e: raise HTTPException(502, str(e))
    with db() as c: c.execute("UPDATE scans SET data=? WHERE id=?", (json.dumps(d), i))
    return d["anchor"]

app.mount("/", StaticFiles(directory=str(ROOT / "frontend"), html=True), name="ui")
