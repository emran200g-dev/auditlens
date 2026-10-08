"""Compile and deploy AuditAttestation to Sepolia.
   pip install web3 py-solc-x
   PRIVATE_KEY=0x... python contracts/deploy.py
   Then put the printed address in CONTRACT_ADDRESS (.env)."""
import os
from pathlib import Path
import solcx
from web3 import Web3

solcx.install_solc("0.8.24")
src = (Path(__file__).parent / "AuditAttestation.sol").read_text()
out = solcx.compile_source(src, output_values=["abi", "bin"], solc_version="0.8.24")
_, iface = next(iter(out.items()))
w3 = Web3(Web3.HTTPProvider(os.environ.get("SEPOLIA_RPC", "https://ethereum-sepolia-rpc.publicnode.com")))
acct = w3.eth.account.from_key(os.environ["PRIVATE_KEY"])
C = w3.eth.contract(abi=iface["abi"], bytecode=iface["bin"])
tx = C.constructor().build_transaction({"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address), "chainId": 11155111})
h = w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction)
rc = w3.eth.wait_for_transaction_receipt(h)
print("CONTRACT_ADDRESS=" + rc.contractAddress)
