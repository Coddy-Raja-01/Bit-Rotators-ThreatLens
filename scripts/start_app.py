import os
import subprocess
import sys
import time
from pathlib import Path

from web3 import HTTPProvider, Web3

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.web3_service import RegistryUnavailable, _registry, deploy_registry  # noqa: E402


def start():
    rpc_url = os.getenv("WEB3_PROVIDER_URI", "http://127.0.0.1:8545")
    web3 = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": 3}))
    deadline = time.monotonic() + int(os.getenv("WEB3_STARTUP_TIMEOUT", "90"))
    while time.monotonic() < deadline and not web3.is_connected():
        print(f"Waiting for Ethereum RPC at {rpc_url}...", flush=True)
        time.sleep(2)
    if not web3.is_connected():
        raise RegistryUnavailable(f"Ethereum RPC at {rpc_url} did not become available.")

    try:
        _registry(web3)
        print("ThreatRegistry contract is ready.", flush=True)
    except RegistryUnavailable as exc:
        if web3.eth.chain_id != 31337 or not any(
            phrase in str(exc).lower()
            for phrase in ("not deployed", "no contract code")
        ):
            raise
        deployment = deploy_registry()
        print(f"Deployed ThreatRegistry at {deployment['address']}.", flush=True)

    return subprocess.call([sys.executable, str(ROOT / "scripts" / "run_server.py")], cwd=ROOT)


if __name__ == "__main__":
    try:
        raise SystemExit(start())
    except RegistryUnavailable as exc:
        print(f"ThreatLens startup failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
