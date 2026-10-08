"""Real chain access over JSON-RPC: anchor verification and on-chain governance evidence."""
import os, httpx

RPCS = {1: "https://ethereum-rpc.publicnode.com", 11155111: "https://ethereum-sepolia-rpc.publicnode.com", 8453: "https://base-rpc.publicnode.com",
        42161: "https://arbitrum-one-rpc.publicnode.com", 10: "https://optimism-rpc.publicnode.com", 137: "https://polygon-bor-rpc.publicnode.com"}
SEL_ANCHOR, SEL_VERIFY = "0x1a8512ea", "0x75e36616"
EVENT_TOPIC = "0x10995ea74695da8b6a7bd01a5b09b98d5d320364d5391141861688e65b5f1dcb"   # ReportAnchored(bytes32,address,string,uint64)
SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"      # EIP-1967 proxy admin
ZERO = "0x" + "0" * 40

class Pending(Exception): pass

def rpc(chain, method, params):
    url = os.getenv(f"RPC_{chain}") or (os.getenv("SEPOLIA_RPC") if chain == 11155111 else None) or RPCS.get(chain)
    if not url: raise RuntimeError(f"No RPC endpoint for chain {chain}")
    try: r = httpx.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=20).json()
    except httpx.HTTPError as e: raise RuntimeError(f"RPC unreachable: {type(e).__name__}")
    if "error" in r: raise RuntimeError(str(r["error"].get("message", "rpc error")))
    return r["result"]

def call(chain, to, data):
    try: return rpc(chain, "eth_call", [{"to": to, "data": data}, "latest"])
    except RuntimeError: return None

def _holder(chain, addr, label):
    """Classify who controls a privileged slot, using bytecode and Safe/Timelock getters."""
    if addr.lower() == ZERO:
        return dict(severity="Low", title=f"{label} is renounced (zero address)", why="No one can use the privileged functions; confirm this is intended and that nothing needs an admin.", fix="", detail=[f"{label} = {addr}"])
    code = rpc(chain, "eth_getCode", [addr, "latest"])
    if code in ("0x", "0x0", ""):
        return dict(severity="High", title=f"{label} is a single externally-owned account", why="One private key controls every privileged function. A leaked or phished key means immediate loss, with no delay and no co-signers.",
                    fix="Move the role to a multisig (e.g. Safe) and put a timelock in front of sensitive calls.", detail=[f"{label} = {addr} (no contract code at this address on chain {chain})"])
    d = call(chain, addr, "0xf27a0c92")
    if d and len(d) >= 66 and int(d, 16) > 0:
        s = int(d, 16); return dict(severity="Low", title=f"{label} is a timelock (min delay {s}s)", why="Privileged actions are delayed, giving users time to exit. Check who proposes and who can cancel.", fix="", detail=[f"{label} = {addr}", f"getMinDelay() = {s}"])
    t = call(chain, addr, "0xe75235b8")
    if t and len(t) >= 66 and int(t, 16) > 0:
        n = int(t, 16); sev = "Medium" if n < 3 else "Low"
        return dict(severity=sev, title=f"{label} is a multisig with threshold {n}", why="Several signers must approve. Thresholds below 3, or no timelock on top, still allow a fast coordinated or coerced change.", fix="Prefer 3+ signers with a timelock for upgrades and parameter changes." if sev != "Low" else "", detail=[f"{label} = {addr}", f"getThreshold() = {n}"])
    return dict(severity="Medium", title=f"{label} is a contract of unrecognised type", why="It has code but exposes neither Safe nor TimelockController getters, so its signer set and delay can't be established automatically.", fix="Document and review its access rules manually.", detail=[f"{label} = {addr}"])

def governance_evidence(address, chain):
    items, note = [], None
    try:
        o = call(chain, address, "0x8da5cb5b")
        if o and len(o) >= 66: items.append(_holder(chain, "0x" + o[-40:], "owner()"))
        adm = rpc(chain, "eth_getStorageAt", [address, SLOT_ADMIN, "latest"])
        if adm and int(adm, 16): items.append(_holder(chain, "0x" + adm[-40:], "EIP-1967 proxy admin"))
        if not items: note = "No owner() getter or EIP-1967 admin found on-chain."
    except RuntimeError as e: note = f"On-chain governance lookup failed: {e}"
    return items, note

def verify_anchor(chain, tx_hash, report_hash_hex, contract):
    """Confirm tx_hash really anchored report_hash on `contract`: mined, succeeded, right target, right calldata, event emitted, contract state agrees."""
    tx = rpc(chain, "eth_getTransactionByHash", [tx_hash])
    if not tx: raise ValueError("Transaction not found on Sepolia.")
    rc = rpc(chain, "eth_getTransactionReceipt", [tx_hash])
    if not rc: raise Pending("Transaction is not mined yet. Try again in a few seconds.")
    h = report_hash_hex.lower().removeprefix("0x"); c = contract.lower()
    if rc.get("status") != "0x1": raise ValueError("Transaction reverted.")
    if (rc.get("to") or "").lower() != c: raise ValueError("Transaction was not sent to the attestation contract.")
    inp = tx["input"].lower()
    if not inp.startswith(SEL_ANCHOR) or inp[10:74] != h: raise ValueError("Transaction calldata does not anchor this report's hash.")
    if not any(l["address"].lower() == c and l["topics"][0] == EVENT_TOPIC and l["topics"][1][2:] == h for l in rc["logs"]): raise ValueError("No ReportAnchored event for this hash in the receipt.")
    v = call(chain, contract, SEL_VERIFY + h)
    if not v or int(v[2:66], 16) != 1 or "0x" + v[90:130] != tx["from"].lower(): raise ValueError("Contract state does not show this hash anchored by the sender.")
    return dict(tx=tx_hash, block=int(rc["blockNumber"], 16), auditor=tx["from"], timestamp=int(v[2 + 128:2 + 192], 16))
