"""Integration test. Uses local STUB servers for the LLM API and Sepolia RPC so the real code paths run without keys or network.
Run: pip install jsdom (in tests/) ; python tests/test_e2e.py. Not a substitute for a run against the real services."""
import os, sys, json, threading, time, re
os.environ.update(AUDITLENS_DB="/tmp/auditlens-test.db", SEPOLIA_RPC="http://127.0.0.1:9001/rpc", RPC_1="http://127.0.0.1:9001/rpc1",
                  CONTRACT_ADDRESS="0x" + "ab" * 20, RATE_LIMIT_PER_HOUR="100", ZEN_BASE_URL="http://127.0.0.1:9001/zen")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
from fastapi import FastAPI, Request
import uvicorn
ST = {}
stub = FastAPI()
@stub.post("/v1/messages")
async def msg(r: Request):
    b = await r.json(); p = b["messages"][-1]["content"]; ST.setdefault("prompts", []).append(p[:80])
    T = lambda t: {"content": [{"type": "text", "text": t}]}
    if "LOGIC, ACCESS-CONTROL" in p:
        return T(json.dumps([{"title": "Anyone can take ownership", "file": "Contract.sol", "line": 24, "snippet": "owner = n;", "likelihood": 5, "impact": 5, "explanation": "setOwner has no caller check."},
                             {"title": "Hallucinated bug", "file": "Contract.sol", "line": 10, "snippet": "this line does not exist anywhere", "likelihood": 5, "impact": 5, "explanation": "x"}]))
    if "writing for a GRC audience" in p:
        ids = re.findall(r'"id": "(F\d+)"', p)
        return T("```json\n" + json.dumps([{"id": i, "explanation": "AI says: " + i, "risk_statement": "biz", "fix": "do X", "fix_code": "// fix", "exploit": ["call it", "profit"], "poc": "contract T {}",
                 "owasp": "SC01 Access Control", "iso": ["A.8.2 Privileged access"], "soc2": ["CC6.1 Logical access"] if i == "F1" else ["BOGUS 9.9"]} for i in ids]) + "\n```")
    if "GOVERNANCE and CENTRALIZATION" in p:
        return T(json.dumps([{"severity": "High", "title": "Owner can mint unlimited", "file": "Contract.sol", "line": 33, "snippet": "balances[to] += a;", "why": "w", "fix": "f"},
                             {"severity": "High", "title": "fake", "file": "Contract.sol", "line": 1, "snippet": "nonexistent code", "why": "w", "fix": "f"}]))
    if "corrected Solidity" in p:
        src = p.split("FILE Contract.sol:\n", 1)[1]; return T(src.replace("function setOwner(address n) external {", "function setOwner(address n) external onlyOwner {"))
    if "still contain this vulnerability" in p: return T('{"still_present": false, "reason": "setOwner is now onlyOwner"}')
    return T("Fix F1 first: " + ("setOwner" in b.get("system", "") and "system had source" or "no source"))
@stub.post("/zen/chat/completions")
async def zen(r: Request):
    b = await r.json(); assert r.headers["authorization"] == "Bearer zenkey", "bad auth header"
    sysm = [m["content"] for m in b["messages"] if m["role"] == "system"]
    class R:
        async def json(self): return {"messages": [m for m in b["messages"] if m["role"] != "system"], "system": sysm[0] if sysm else ""}
    out = await msg(R()); return {"choices": [{"message": {"content": "<think>reasoning...</think>" + out["content"][0]["text"]}}]}
@stub.post("/rpc")
async def rpc(r: Request):
    b = await r.json(); m, a = b["method"], b["params"]; R = lambda x: {"jsonrpc": "2.0", "id": 1, "result": x}
    if m == "eth_getTransactionByHash": return R(ST["txs"].get(a[0]))
    if m == "eth_getTransactionReceipt": return R(ST["rcs"].get(a[0]))
    if m == "eth_call": return R(ST["verify"].get(a[0]["data"], "0x" + "0" * 64 * 5))
@stub.post("/rpc1")
async def rpc1(r: Request):
    b = await r.json(); m, a = b["method"], b["params"]; R = lambda x: {"jsonrpc": "2.0", "id": 1, "result": x}
    if m == "eth_call": return R("0x" + "0" * 24 + "cd" * 20) if a[0]["data"] == "0x8da5cb5b" else R("0x")
    if m == "eth_getStorageAt": return R("0x" + "0" * 64)
    if m == "eth_getCode": return R("0x")
threading.Thread(target=lambda: uvicorn.run(stub, port=9001, log_level="error"), daemon=True).start(); time.sleep(1.5)

from fastapi.testclient import TestClient
import main, engine
c = TestClient(main.app)
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "VulnerableVault.sol")).read()
ok = lambda n, cond, info="": print(("PASS " if cond else "FAIL ") + n, info if not cond else "")

# 1. no engine at all -> honest 503, no fake results
os.environ.pop("OPENCODE_ZEN_API_KEY", None)
r = c.post("/api/scan", json={"source": src}); ok("503 when no engine", r.status_code == 503 and "No analysis engine" in r.json()["detail"], r.text)

# 2. AI path (no Slither in sandbox)
os.environ["OPENCODE_ZEN_API_KEY"] = "zenkey"
r = c.post("/api/scan", json={"address": None, "source": src}); d = r.json(); ok("scan ok", r.status_code == 200, r.text[:300])
F = d["findings"]; titles = [f["title"] for f in F]
ok("AI finding grounded, line corrected", any(f["key"] == "logic" and f["line"] == 24 for f in F), titles)
ok("hallucinated AI finding dropped", not any("Hallucinated" in t for t in titles))
ok("old-solc via pragma", any(f["key"] == "old-solc" for f in F))
ok("exploit + poc present", all(f["exploit"] and f["poc"] for f in F))
ok("catalog-valid mapping accepted", F[0]["mapping"].startswith("ai-selected"), F[0]["mapping"])
ok("invalid control id rejected -> reference table", any(f["mapping"].startswith("reference") for f in F[1:]), [f["mapping"] for f in F])
g = d["governance"]; ok("governance grounded", len(g["items"]) == 1 and "mint" in g["items"][0]["title"], g)
ok("engine honest about no slither", d["engine"]["slither"] is False and "not installed" in d["engine"]["note"])
sid, h = d["id"], d["report_sha256"]
ok("pdf hash stable", __import__("hashlib").sha256(c.get(f"/api/scans/{sid}/report.pdf").content).hexdigest() == h)

# 2b. Provider/model reporting (OpenAI-compatible Zen, <think> stripping is exercised by every call)
ok("config reports zen provider", c.get("/api/config").json()["provider"] == "zen" and c.get("/api/config").json()["model"] == "space-bunny-free")
rz = c.post("/api/scan", json={"source": src}); dz = rz.json(); ok("scan via Zen works", rz.status_code == 200 and any(f["key"] == "logic" and f["line"] == 24 for f in dz["findings"]) and dz["findings"][0]["exploit"], rz.text[:300])
# 2c. rate limit
os.environ["RATE_LIMIT_PER_HOUR"] = "2"; hh = {"x-forwarded-for": "9.9.9.9"}
codes = [c.post("/api/scan", json={"source": src}, headers=hh).status_code for _ in range(3)]; ok("rate limit blocks 3rd call", codes == [200, 200, 429], codes)
os.environ["RATE_LIMIT_PER_HOUR"] = "100"

# 3. verify fix
lg = next(f for f in F if f["key"] == "logic")
r = c.post(f"/api/scans/{sid}/findings/{lg['id']}/verify-fix"); j = r.json(); ok("verify-fix resolves", r.status_code == 200 and j["resolved"] and "onlyOwner" in j["diff"], r.text[:300])
ok("verify-fix says which engine", "AI re-audit only" in j["rescan_engine"], j["rescan_engine"])

# 4. chat
r = c.post(f"/api/scans/{sid}/chat", json={"messages": [{"role": "user", "content": "what first?"}]}); ok("chat gets source in system prompt", "system had source" in r.json().get("reply", ""), r.text)
r = c.post(f"/api/scans/{sid}/chat", json={"messages": [{"role": "assistant", "content": "x"}]}); ok("chat rejects bad turn order", r.status_code == 400)

# 5. anchor verification against a stub chain
C = os.environ["CONTRACT_ADDRESS"]; A = "0x" + "11" * 20; TX = "0x" + "aa" * 32
call = "0x1a8512ea" + h + "0" * 64
ev = {"address": C, "topics": [engine.chain.EVENT_TOPIC, "0x" + h, "0x" + "0" * 24 + "11" * 20]}
ST["txs"] = {TX: {"input": call, "from": A}}; ST["rcs"] = {}
ST["verify"] = {"0x75e36616" + h: "0x" + "0" * 63 + "1" + "0" * 24 + "11" * 20 + hex(1700000000)[2:].rjust(64, "0")}
r = c.post(f"/api/scans/{sid}/anchor", json={"tx": TX}); ok("pending tx -> 409", r.status_code == 409, r.text)
ST["rcs"][TX] = {"status": "0x1", "to": C, "blockNumber": "0x10", "logs": [ev]}
BAD = "0x" + "bb" * 32
ST["txs"][BAD] = {"input": "0x1a8512ea" + "ff" * 32 + "0" * 64, "from": A}; ST["rcs"][BAD] = {"status": "0x1", "to": C, "blockNumber": "0x10", "logs": [ev]}
r = c.post(f"/api/scans/{sid}/anchor", json={"tx": BAD}); ok("wrong hash rejected", r.status_code == 400 and "calldata" in r.text, r.text)
ST["rcs"][TX]["to"] = "0x" + "cc" * 20
r = c.post(f"/api/scans/{sid}/anchor", json={"tx": TX}); ok("wrong contract rejected", r.status_code == 400 and "not sent" in r.text, r.text)
ST["rcs"][TX]["to"] = C; ST["rcs"][TX]["status"] = "0x0"
r = c.post(f"/api/scans/{sid}/anchor", json={"tx": TX}); ok("reverted tx rejected", r.status_code == 400, r.text)
ST["rcs"][TX]["status"] = "0x1"; r = c.post(f"/api/scans/{sid}/anchor", json={"tx": "0x" + "dd" * 32}); ok("unknown tx rejected", r.status_code == 400, r.text)
r = c.post(f"/api/scans/{sid}/anchor", json={"tx": TX}); ok("valid anchor accepted", r.status_code == 200 and r.json()["block"] == 16 and r.json()["timestamp"] == 1700000000, r.text)
ok("anchor persisted", c.get(f"/api/scans/{sid}").json()["anchor"]["auditor"] == A)

# 6. on-chain governance (stub chain 1: owner() is an EOA)
ev2, note = engine.chain.governance_evidence("0x" + "ee" * 20, 1); ok("on-chain EOA owner flagged High", ev2 and ev2[0]["severity"] == "High" and "externally-owned" in ev2[0]["title"], (ev2, note))
print("static: frontend served ->", c.get("/").status_code)

# 7. real browser-like DOM test of the frontend against a live server
import subprocess
threading.Thread(target=lambda: uvicorn.run(main.app, port=8000, log_level="error"), daemon=True).start(); time.sleep(1.5)
js = r'''
const {JSDOM}=require("jsdom");const sid=process.argv[2];
(async()=>{
const dom=await JSDOM.fromURL("http://127.0.0.1:8000/",{runScripts:"dangerously",resources:"usable",pretendToBeVisual:true,beforeParse(w){w.Element.prototype.scrollIntoView=()=>{};w.scrollTo=()=>{};w.fetch=(u,o)=>fetch(new URL(u,"http://127.0.0.1:8000/"),o)}});
const w=dom.window,d=w.document,wait=ms=>new Promise(r=>setTimeout(r,ms)),out=[];
const chk=(n,c)=>out.push((c?"PASS ":"FAIL ")+n);
await wait(1200);chk("scan view renders",!!d.querySelector("#go"));
for(const [tab,probe] of [["","Verify fix by re-scanning"],["/grc","Risk register"],["/governance","on-chain"],["/chat","Ask the audit"],["/report","Verify a report"]]){
 w.location.hash="#/s/"+sid+tab;await wait(900);chk("view "+(tab||"findings")+" renders '"+probe+"'",d.body.textContent.includes(probe)&&!d.body.textContent.includes("Something went wrong"));}
w.location.hash="#/s/"+sid;await wait(900);
chk("exploit steps shown",d.body.textContent.includes("Exploit scenario"));
d.querySelector(".vf").click();await wait(1500);chk("verify-fix result rendered",/Resolved|Not resolved/.test(d.body.textContent));
w.location.hash="#/s/"+sid+"/chat";await wait(800);d.querySelector("#q").value="what first?";d.querySelector("#send").click();await wait(1200);chk("chat reply rendered",d.body.textContent.includes("Fix F1 first"));
w.location.hash="#/history";await wait(800);chk("history lists scan",d.querySelectorAll("tr.link").length>=1);
console.log(out.join("\n"));process.exit(0)})()
'''
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "dom.js"), "w").write(js)
q = subprocess.run(["node", os.path.join(os.path.dirname(os.path.abspath(__file__)), "dom.js"), sid], capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)), timeout=90); print(q.stdout, q.stderr[-1500:], q.returncode)
