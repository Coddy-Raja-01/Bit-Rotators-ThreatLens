import json
from pathlib import Path

import solcx


ROOT = Path(__file__).resolve().parent.parent
SOLC_VERSION = "0.8.20"
SOURCE_PATH = ROOT / "contracts" / "ThreatRegistry.sol"
ARTIFACT_PATH = ROOT / "contracts" / "artifacts" / "ThreatRegistry.json"
DEPLOYMENT_ARTIFACT_PATH = ROOT / "deployments" / "ThreatRegistry.json"


def compile_contract() -> dict:
    installed = {str(version) for version in solcx.get_installed_solc_versions()}
    if SOLC_VERSION not in installed:
        solcx.install_solc(SOLC_VERSION)

    compiled = solcx.compile_source(
        SOURCE_PATH.read_text(encoding="utf-8"),
        output_values=["abi", "bin"],
        solc_version=SOLC_VERSION,
        optimize=True,
        optimize_runs=200,
    )
    contract = compiled["<stdin>:ThreatRegistry"]
    artifact = {
        "contractName": "ThreatRegistry",
        "compilerVersion": SOLC_VERSION,
        "abi": contract["abi"],
        "bytecode": "0x" + contract["bin"],
    }
    serialized = json.dumps(artifact, indent=2) + "\n"
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_PATH.write_text(serialized, encoding="utf-8")
    DEPLOYMENT_ARTIFACT_PATH.write_text(serialized, encoding="utf-8")
    print(f"Compiled {SOURCE_PATH} to {ARTIFACT_PATH} and {DEPLOYMENT_ARTIFACT_PATH}")
    return artifact


if __name__ == "__main__":
    compile_contract()
