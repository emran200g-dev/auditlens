"""Knowledge base: finding type -> risk model + control mappings. Deterministic and auditable on purpose."""
FRAMEWORKS = {
    "owasp": {"name": "OWASP Smart Contract Top 10", "controls": [
        "SC01 Access Control", "SC02 Price Oracle", "SC03 Logic Errors", "SC04 Input Validation", "SC05 Reentrancy",
        "SC06 Unchecked Calls", "SC07 Flash Loans", "SC08 Overflow", "SC09 Randomness", "SC10 DoS"]},
    "iso": {"name": "ISO 27001:2022 Annex A", "controls": [
        "A.5.15 Access control", "A.8.2 Privileged access", "A.8.8 Vulnerability mgmt", "A.8.28 Secure coding", "A.8.32 Change mgmt"]},
    "soc2": {"name": "SOC 2 Trust Criteria", "controls": [
        "CC6.1 Logical access", "CC6.3 Role-based access", "CC7.1 Vuln detection", "CC8.1 Change mgmt"]},
}

def severity(risk: int) -> str:
    return "Critical" if risk >= 20 else "High" if risk >= 12 else "Medium" if risk >= 6 else "Low"

# L = default likelihood (1-5), I = impact (1-5). Slither confidence overrides L when available.
KB = {
 "reentrancy": dict(t="Reentrancy in value transfer", L=4, I=5, o="SC05 Reentrancy", i=["A.8.28 Secure coding"], s=["CC7.1 Vuln detection"], own="Smart contract lead",
   x="State is updated after ETH is sent, so a malicious receiver can re-enter and withdraw repeatedly before the balance drops.",
   f="Apply checks-effects-interactions and add a reentrancy guard.", c="balances[msg.sender] = 0;\n(bool ok,) = msg.sender.call{value: amt}(\"\");\nrequire(ok);  // + OpenZeppelin ReentrancyGuard"),
 "tx-origin": dict(t="Authorization with tx.origin", L=4, I=4, o="SC01 Access Control", i=["A.5.15 Access control", "A.8.2 Privileged access"], s=["CC6.1 Logical access"], own="Smart contract lead",
   x="tx.origin is the wallet that started the transaction. If the owner is lured into calling a malicious contract, that contract passes the check.",
   f="Authorize with msg.sender.", c="require(msg.sender == owner, \"not owner\");"),
 "access-control": dict(t="Privileged function without access control", L=5, I=5, o="SC01 Access Control", i=["A.8.2 Privileged access", "A.5.15 Access control"], s=["CC6.1 Logical access", "CC6.3 Role-based access"], own="Security / protocol owner",
   x="This function changes critical state or moves funds and nothing checks the caller, so anyone can invoke it.",
   f="Gate it with onlyOwner or role-based AccessControl.", c="function setOwner(address n) external onlyOwner { owner = n; }"),
 "unchecked-call": dict(t="Unchecked low-level call", L=4, I=3, o="SC06 Unchecked Calls", i=["A.8.28 Secure coding"], s=["CC7.1 Vuln detection"], own="Smart contract lead",
   x="send/call return false on failure instead of reverting. The result is ignored, so accounting can diverge from what actually happened.",
   f="Check the return value and revert on failure.", c="(bool ok,) = to.call{value: amt}(\"\");\nrequire(ok, \"call failed\");"),
 "arbitrary-send": dict(t="ETH sent to an arbitrary destination", L=3, I=5, o="SC01 Access Control", i=["A.8.2 Privileged access"], s=["CC6.1 Logical access"], own="Security / protocol owner",
   x="ETH can be sent to an address the caller controls, and the function is not restricted to a trusted role.",
   f="Restrict who can call it and where funds can go.", c="require(msg.sender == treasuryAdmin);"),
 "selfdestruct": dict(t="Contract can be destroyed", L=3, I=5, o="SC03 Logic Errors", i=["A.8.32 Change mgmt"], s=["CC8.1 Change mgmt"], own="Protocol owner",
   x="selfdestruct can permanently remove the contract and send its balance away if the caller is not tightly controlled.",
   f="Remove selfdestruct, or put it behind governance.", c=""),
 "delegatecall": dict(t="Delegatecall to a controllable target", L=3, I=5, o="SC03 Logic Errors", i=["A.8.32 Change mgmt", "A.8.8 Vulnerability mgmt"], s=["CC8.1 Change mgmt"], own="Protocol owner",
   x="delegatecall runs foreign code against this contract's storage. A controllable target means full takeover.",
   f="Allowlist targets and guard the call.", c="require(allowedImpl[target]);"),
 "old-solc": dict(t="No overflow protection (Solidity < 0.8)", L=3, I=4, o="SC08 Overflow", i=["A.8.28 Secure coding"], s=["CC7.1 Vuln detection"], own="Smart contract lead",
   x="Before 0.8, arithmetic wraps silently and no SafeMath is imported, so balances can under/overflow.",
   f="Compile with Solidity 0.8 or later.", c="pragma solidity ^0.8.20;"),
 "weak-prng": dict(t="Block data used as randomness", L=4, I=3, o="SC09 Randomness", i=["A.8.28 Secure coding"], s=["CC7.1 Vuln detection"], own="Smart contract lead",
   x="Validators can influence block values and other contracts can read them in the same transaction, so outcomes are predictable.",
   f="Use verifiable randomness such as Chainlink VRF.", c=""),
 "timestamp": dict(t="Logic depends on block.timestamp", L=2, I=3, o="SC03 Logic Errors", i=["A.8.28 Secure coding"], s=["CC7.1 Vuln detection"], own="Smart contract lead",
   x="Block producers can shift timestamps slightly. Comparisons that decide money or access can be nudged.",
   f="Do not rely on exact timestamps for critical decisions.", c=""),
 "dos-loop": dict(t="Unbounded loop with external calls (DoS)", L=3, I=3, o="SC10 DoS", i=["A.8.8 Vulnerability mgmt"], s=["CC7.1 Vuln detection"], own="Smart contract lead",
   x="Paying a growing list in one transaction can exceed the gas limit, or one failing recipient can block everyone.",
   f="Use pull payments or paginate.", c="mapping(address=>uint) public owed;\nfunction claim() external { /* pay msg.sender only */ }"),
 "logic": dict(t="Logic flaw (AI audit)", L=3, I=4, o="SC03 Logic Errors", i=["A.8.28 Secure coding"], s=["CC7.1 Vuln detection"], own="Smart contract lead",
   x="Found by the AI auditor reading the code.", f="See suggested fix.", c=""),
 "generic": dict(t="Static-analysis finding", L=3, I=3, o="SC03 Logic Errors", i=["A.8.8 Vulnerability mgmt"], s=["CC7.1 Vuln detection"], own="Smart contract lead",
   x="Reported by the static analyzer.", f="Review the analyzer description and fix accordingly.", c=""),
}

SLITHER_MAP = {
 "reentrancy-eth": "reentrancy", "reentrancy-no-eth": "reentrancy", "tx-origin": "tx-origin",
 "unchecked-lowlevel": "unchecked-call", "unchecked-send": "unchecked-call", "arbitrary-send-eth": "arbitrary-send",
 "suicidal": "selfdestruct", "controlled-delegatecall": "delegatecall", "delegatecall-loop": "delegatecall",
 "weak-prng": "weak-prng", "timestamp": "timestamp", "calls-loop": "dos-loop", "unprotected-upgrade": "access-control",
}
