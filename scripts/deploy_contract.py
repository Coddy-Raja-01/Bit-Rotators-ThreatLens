import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.web3_service import (  # noqa: E402
    RegistryUnavailable,
    _web3,
    deploy_registry,
)


if __name__ == "__main__":
    try:
        web3 = _web3()
        deployment_path = ROOT / "deployments" / "local.json"
        if deployment_path.exists():
            try:
                deployment = json.loads(deployment_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                deployment = {}
            address = deployment.get("address")
            if deployment.get("chainId") == web3.eth.chain_id and address:
                if web3.eth.get_code(address):
                    print(f"ThreatRegistry is already deployed at {address} on chain {web3.eth.chain_id}.")
                    raise SystemExit(0)
        metadata = deploy_registry()
        print(
            f"Deployed ThreatRegistry at {metadata['address']} "
            f"on chain {metadata['chainId']} in transaction {metadata['deploymentTx']}."
        )
    except RegistryUnavailable as exc:
        print(f"Deployment failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
