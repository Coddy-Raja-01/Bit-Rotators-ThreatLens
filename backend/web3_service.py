import json
import os
from pathlib import Path

from eth_account import Account
from hexbytes import HexBytes
from web3 import HTTPProvider, Web3

from backend.database import get_db

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_PATH = ROOT / "contracts" / "artifacts" / "ThreatRegistry.json"
DEPLOYMENT_PATH = ROOT / "deployments" / "local.json"
DEFAULT_RPC_URL = "http://127.0.0.1:8545"
REPORT_STATUSES = {0: "Active", 1: "Disputed", 2: "Revised"}
CLASSIFICATION_CATEGORIES = {
    "Low Risk": 0,
    "Suspicious": 1,
    "High Risk": 2,
    "Confirmed Malicious": 3,
    "Inconclusive": 4,
}


class RegistryUnavailable(RuntimeError):
    """Raised when the configured Ethereum RPC or deployed registry is unavailable."""


def canonical_json_bytes(obj: dict) -> bytes:
    """Serialize a report deterministically before hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_keccak256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return Web3.to_hex(Web3.keccak(data))


def compute_report_hashes(report: dict) -> tuple[str, str]:
    target = report.get("target", {})
    domain = (target.get("hostname") or target.get("normalized_url") or "").lower().strip()
    clean_report = {
        key: value
        for key, value in report.items()
        if key not in ("on_chain_commitment", "web3_receipt")
    }
    return compute_keccak256(canonical_json_bytes(clean_report)), compute_keccak256(domain)


def _read_artifact() -> dict:
    try:
        artifact = json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryUnavailable(
            f"ThreatRegistry artifact is unavailable at {ARTIFACT_PATH}; run scripts/compile_contract.py."
        ) from exc
    if not artifact.get("abi"):
        raise RegistryUnavailable("ThreatRegistry artifact has no ABI; recompile the contract.")
    return artifact


def _load_deployment(chain_id: int) -> dict:
    address = os.getenv("THREAT_REGISTRY_ADDRESS", "").strip()
    if address:
        return {
            "address": address,
            "chainId": chain_id,
            "deployment_block": int(os.getenv("THREAT_REGISTRY_DEPLOYMENT_BLOCK", "0")),
        }

    try:
        deployment = json.loads(DEPLOYMENT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise RegistryUnavailable(
            "ThreatRegistry is not deployed. Start the local chain and run scripts/deploy_contract.py."
        )
    if deployment.get("chainId") != chain_id:
        raise RegistryUnavailable(
            f"Deployment metadata is for chain {deployment.get('chainId')}, but RPC is chain {chain_id}. "
            "Deploy ThreatRegistry to the configured chain."
        )
    if not deployment.get("address"):
        raise RegistryUnavailable(
            "ThreatRegistry is not deployed. Start the local chain and run scripts/deploy_contract.py."
        )
    return deployment


def _web3() -> Web3:
    rpc_url = os.getenv("WEB3_PROVIDER_URI", DEFAULT_RPC_URL).strip()
    if not rpc_url:
        raise RegistryUnavailable("Set WEB3_PROVIDER_URI to an Ethereum JSON-RPC endpoint.")
    web3 = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
    try:
        connected = web3.is_connected()
    except Exception as exc:
        raise RegistryUnavailable(f"Could not connect to Ethereum RPC {rpc_url}: {exc}") from exc
    if not connected:
        raise RegistryUnavailable(
            f"Ethereum RPC {rpc_url} is unavailable. Start the app and chain with docker compose up."
        )
    return web3


def _registry(web3: Web3 | None = None):
    web3 = web3 or _web3()
    artifact = _read_artifact()
    deployment = _load_deployment(web3.eth.chain_id)
    try:
        address = Web3.to_checksum_address(deployment["address"])
    except (KeyError, ValueError) as exc:
        raise RegistryUnavailable("ThreatRegistry deployment address is invalid.") from exc
    if not web3.eth.get_code(address):
        raise RegistryUnavailable(
            f"No contract code exists at {address} on chain {web3.eth.chain_id}; redeploy ThreatRegistry."
        )
    contract = web3.eth.contract(address=address, abi=artifact["abi"])
    return web3, contract, deployment


def _send_transaction(web3: Web3, function, sender: str | None = None):
    private_key = os.getenv("WEB3_RELAYER_PRIVATE_KEY", "").strip()
    if private_key:
        account = Account.from_key(private_key)
        if sender and Web3.to_checksum_address(sender) != account.address:
            raise RegistryUnavailable("Configured reporter address does not match the relayer private key.")
        transaction = function.build_transaction({
            "from": account.address,
            "nonce": web3.eth.get_transaction_count(account.address),
            "chainId": web3.eth.chain_id,
        })
        signed = account.sign_transaction(transaction)
        tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    else:
        accounts = web3.eth.accounts
        if not accounts:
            raise RegistryUnavailable(
                "The RPC has no unlocked accounts. Configure WEB3_RELAYER_PRIVATE_KEY or an unlocked local account."
            )
        requested = sender or os.getenv("WEB3_RELAYER_ADDRESS") or accounts[0]
        sender = Web3.to_checksum_address(requested)
        if sender not in [Web3.to_checksum_address(account) for account in accounts]:
            raise RegistryUnavailable(
                f"Account {sender} is not unlocked by this RPC. Configure WEB3_RELAYER_PRIVATE_KEY."
            )
        tx_hash = function.transact({"from": sender})

    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    if receipt.status != 1:
        raise RegistryUnavailable(f"ThreatRegistry transaction {tx_hash.hex()} reverted.")
    return receipt


def _format_record(record) -> dict:
    return {
        "on_chain_id": int(record[0]),
        "report_hash": Web3.to_hex(record[1]),
        "domain_hash": Web3.to_hex(record[2]),
        "category": int(record[3]),
        "evidence_ref": record[4],
        "reporter": Web3.to_checksum_address(record[5]),
        "timestamp": int(record[6]),
        "revision": int(record[7]),
        "status": REPORT_STATUSES[int(record[8])],
        "confirmations": int(record[9]),
        "disputes": int(record[10]),
    }


def _receipt_data(web3: Web3, receipt, record: dict, report_id: str) -> dict:
    block = web3.eth.get_block(receipt.blockNumber)
    return {
        "success": True,
        **record,
        "report_id": report_id,
        "tx_hash": Web3.to_hex(receipt.transactionHash),
        "block_number": int(receipt.blockNumber),
        "timestamp": int(block.timestamp),
        "network": os.getenv("WEB3_NETWORK", f"Chain {web3.eth.chain_id}"),
        "contract_address": receipt.to,
        "explorer_url": None,
        "integrity_scope": "The chain proves this hash was recorded; it does not prove the report's claims are true.",
    }


def get_registry_status() -> dict:
    web3, contract, deployment = _registry()
    return {
        "connected": True,
        "network": os.getenv("WEB3_NETWORK", f"Chain {web3.eth.chain_id}"),
        "chain_id": web3.eth.chain_id,
        "contract_address": contract.address,
        "report_count": int(contract.functions.reportCount().call()),
        "deployment_block": deployment.get("deploymentBlock", deployment.get("deployment_block", 0)),
        "integrity_scope": "On-chain hashes prove record integrity, not the truth of report claims.",
    }


def submit_report_commitment(
    report_dict: dict,
    reporter_address: str | None = None,
    use_relayer: bool = True,
) -> dict:
    report_id = report_dict.get("report_id") or report_dict.get("unified_scoring", {}).get("report_id")
    if not report_id:
        raise ValueError("Report missing stable report_id")

    web3, contract, _ = _registry()
    report_hash, domain_hash = compute_report_hashes(report_dict)
    report_hash_bytes = HexBytes(report_hash)
    domain_hash_bytes = HexBytes(domain_hash)
    existing_id = int(contract.functions.hashToReportId(report_hash_bytes).call())
    if existing_id:
        record = _format_record(contract.functions.getReport(existing_id).call())
        return {
            "success": True,
            "already_committed": True,
            **record,
            "report_id": report_id,
            "network": os.getenv("WEB3_NETWORK", f"Chain {web3.eth.chain_id}"),
            "contract_address": contract.address,
            "explorer_url": None,
            "integrity_scope": "The chain proves this hash was recorded; it does not prove the report's claims are true.",
        }

    scoring = report_dict.get("unified_scoring", {})
    category = CLASSIFICATION_CATEGORIES.get(scoring.get("classification"), 4)
    # Store only the opaque report ID; never place a raw URL or message on-chain.
    function = contract.functions.submitReport(
        report_hash_bytes,
        domain_hash_bytes,
        category,
        str(report_id),
    )
    requested_sender = reporter_address if (reporter_address and not use_relayer) else None
    receipt = _send_transaction(web3, function, requested_sender)
    events = contract.events.ReportSubmitted().process_receipt(receipt)
    if not events:
        raise RegistryUnavailable("Mined registry transaction did not emit ReportSubmitted.")
    record_id = int(events[0]["args"]["id"])
    record = _format_record(contract.functions.getReport(record_id).call())
    return _receipt_data(web3, receipt, record, str(report_id))


def verify_report_integrity(report_dict: dict, simulated_tampering: bool = False) -> dict:
    copied_report = json.loads(json.dumps(report_dict))
    if simulated_tampering:
        scoring = copied_report.get("unified_scoring", {})
        scoring["classification"] = "Low Risk"
        scoring["score"] = 0

    web3, contract, _ = _registry()
    calculated_hash, domain_hash = compute_report_hashes(copied_report)
    exists, record_id, _, _, _, _ = contract.functions.verifyHash(HexBytes(calculated_hash)).call()
    if exists:
        record = _format_record(contract.functions.getReport(record_id).call())
        exists = record["report_hash"].lower() == calculated_hash.lower()
    else:
        record = None

    return {
        "verified": bool(exists),
        "status_code": "TAMPER_FREE" if exists else "MISMATCH_TAMPERED",
        "message": (
            "The report hash matches the current on-chain commitment."
            if exists
            else "No current on-chain commitment matches this report hash."
        ),
        "calculated_hash": calculated_hash,
        "domain_hash": domain_hash,
        "simulated_tampering": simulated_tampering,
        "network": os.getenv("WEB3_NETWORK", f"Chain {web3.eth.chain_id}"),
        "contract_address": contract.address,
        "integrity_scope": "A hash match proves only that these exact bytes were committed, not that the report claims are true.",
        **(record or {}),
    }


def revise_report_commitment(
    on_chain_id: int,
    new_report_dict: dict,
    note: str,
    reporter_address: str | None = None,
) -> dict:
    web3, contract, _ = _registry()
    current = _format_record(contract.functions.getReport(on_chain_id).call())
    new_hash, _ = compute_report_hashes(new_report_dict)
    tx = contract.functions.reviseReport(on_chain_id, HexBytes(new_hash), note.strip())
    receipt = _send_transaction(web3, tx, reporter_address)
    updated = _format_record(contract.functions.getReport(on_chain_id).call())
    return _receipt_data(
        web3,
        receipt,
        {**updated, "old_hash": current["report_hash"], "new_hash": updated["report_hash"]},
        current["evidence_ref"],
    )


def vote_on_chain_report(
    on_chain_id: int,
    voter_address: str,
    vote_type: str,
    reason_hash: str | None = None,
) -> dict:
    if vote_type not in ("confirm", "dispute"):
        raise ValueError("vote_type must be 'confirm' or 'dispute'")
    web3, contract, _ = _registry()
    if vote_type == "confirm":
        function = contract.functions.confirmReport(on_chain_id)
    else:
        reason = reason_hash or compute_keccak256("")
        function = contract.functions.disputeReport(on_chain_id, HexBytes(reason))
    receipt = _send_transaction(web3, function, voter_address)
    record = _format_record(contract.functions.getReport(on_chain_id).call())
    return {
        "success": True,
        **record,
        "tx_hash": Web3.to_hex(receipt.transactionHash),
        "network": os.getenv("WEB3_NETWORK", f"Chain {web3.eth.chain_id}"),
        "integrity_scope": "Votes attest to participant actions, not to the underlying report's truth.",
    }


def list_chain_registry(limit: int = 50) -> list[dict]:
    _, contract, _ = _registry()
    count = int(contract.functions.reportCount().call())
    rows = []
    for record_id in range(count, max(0, count - limit), -1):
        record = _format_record(contract.functions.getReport(record_id).call())
        rows.append(record)
    return rows


def get_chain_report_details(on_chain_id: int) -> dict | None:
    _, contract, _ = _registry()
    if on_chain_id < 1 or on_chain_id > int(contract.functions.reportCount().call()):
        return None
    record = _format_record(contract.functions.getReport(on_chain_id).call())
    history = contract.functions.getRevisionHistory(on_chain_id).call()
    record["revisions"] = [
        {
            "report_hash": Web3.to_hex(item[0]),
            "note": item[1],
            "timestamp": int(item[2]),
        }
        for item in history
    ]
    record["votes"] = []
    return record


def deploy_registry() -> dict:
    """Deploy the compiled registry artifact to the configured RPC chain."""
    web3 = _web3()
    artifact = _read_artifact()
    accounts = web3.eth.accounts
    private_key = os.getenv("WEB3_RELAYER_PRIVATE_KEY", "").strip()
    if private_key:
        deployer = Account.from_key(private_key).address
    elif accounts:
        deployer = Web3.to_checksum_address(os.getenv("WEB3_RELAYER_ADDRESS", accounts[0]))
        if deployer not in [Web3.to_checksum_address(account) for account in accounts]:
            raise RegistryUnavailable(f"Deployer account {deployer} is not unlocked by the RPC.")
    else:
        raise RegistryUnavailable("Configure an unlocked RPC deployer or WEB3_RELAYER_PRIVATE_KEY.")

    factory = web3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    receipt = _send_transaction(web3, factory.constructor(), deployer)
    address = Web3.to_checksum_address(receipt.contractAddress)
    metadata = {
        "network": os.getenv("WEB3_NETWORK", f"Chain {web3.eth.chain_id}"),
        "chainId": web3.eth.chain_id,
        "address": address,
        "deploymentTx": Web3.to_hex(receipt.transactionHash),
        "deploymentBlock": int(receipt.blockNumber),
        "deployer": deployer,
        "rpcUrl": os.getenv("WEB3_PROVIDER_URI", DEFAULT_RPC_URL),
    }
    DEPLOYMENT_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEPLOYMENT_PATH.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata
