#!/usr/bin/env python3
"""Cross-language VERIFY-rejection conformance (SPEC canon §10).

The emit/canon harnesses prove every port produces byte-identical receipts. This
one proves the other half: every port's VERIFIER accepts the published valid
receipts and REJECTS the published ``invalid_receipt_vectors`` (receipts with a
valid Ed25519 signature over non-canonical / duplicate-key bytes — §6 + R10).

Each port exposes a ``--verify`` mode reading ``{"jws","public_key_hex"}`` lines
(the raw 32-byte Ed25519 public key, hex-encoded — a PEM-free key format every
port loads with one call) and writing ``{"verdict":"ACCEPT","id":"sha256:..."}``
or ``{"verdict":"REJECT"}`` per line. Ports whose toolchain is absent are skipped
(not failed).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

REF = Path(__file__).resolve().parent
ROOT = REF.parent
VECTORS = ROOT / "docs" / "spec" / "provenance" / "v1" / "test-vectors.json"

# Per-language --verify invocation: (argv, cwd). Python is handled in-process.
VERIFY_CMD = {
    "go": (["go", "run", "./cmd/emit", "--verify"], REF / "provenance-go"),
    "rust": (
        ["cargo", "run", "--quiet", "--example", "emit", "--", "--verify"],
        REF / "provenance-rs",
    ),
    "typescript": (
        ["npx", "--no-install", "tsx", "src/emit-cli.ts", "--verify"],
        REF / "provenance-ts",
    ),
    "csharp": (
        ["dotnet", "run", "--project", "interop/Interop.csproj", "--", "--verify"],
        REF / "provenance-cs",
    ),
}

LANGS = [
    ("python", lambda: True),
    ("go", lambda: shutil.which("go")),
    ("rust", lambda: shutil.which("cargo")),
    ("typescript", lambda: shutil.which("npx")),
    ("csharp", lambda: shutil.which("dotnet")),
]


def _py_verify(reqs: list[dict]) -> list[dict]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from raucle.provenance import ProvenanceReceipt, _b64url_decode

    out = []
    for r in reqs:
        try:
            receipt = ProvenanceReceipt.from_jws(r["jws"], strict=True)
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(r["public_key_hex"]))
            header_b64, payload_b64, sig_b64 = r["jws"].split(".")
            signing_input = (header_b64 + "." + payload_b64).encode("ascii")
            pub.verify(_b64url_decode(sig_b64), signing_input)  # raises on bad sig
            out.append({"verdict": "ACCEPT", "id": receipt.receipt_hash})
        except Exception:  # noqa: BLE001 - any failure is a REJECT
            out.append({"verdict": "REJECT"})
    return out


def _run_verify(lang: str, reqs: list[dict]) -> list[dict]:
    if lang == "python":
        return _py_verify(reqs)
    cmd, cwd = VERIFY_CMD[lang]
    stdin = "\n".join(json.dumps(r) for r in reqs) + "\n"
    proc = subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{cmd}: {proc.stderr.strip()}")
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def _verify_valid_receipts(ran, valid, valid_reqs) -> bool:
    """Verify every port accepts all valid receipts with matching ids."""
    ok = True
    print("\n=== valid receipts: every port MUST ACCEPT (and match the id) ===")
    for lang in ran:
        verdicts = _run_verify(lang, valid_reqs)
        for v, got in zip(valid, verdicts, strict=True):
            accept = got.get("verdict") == "ACCEPT"
            id_ok = got.get("id") == v["expected_receipt_hash"]
            if not (accept and id_ok):
                ok = False
                print(
                    f"  {lang} {v['name']}: {got} (expected ACCEPT id={v['expected_receipt_hash']})"
                )
        print(f"  {lang}: {'ALL-ACCEPT + id-OK' if ok else 'FAILED'}")
    return ok


def _verify_invalid_receipts(ran, invalid, invalid_reqs) -> bool:
    """Verify every port rejects all invalid receipts."""
    ok = True
    print("\n=== invalid receipts: every port MUST REJECT (§6 / R10) ===")
    for lang in ran:
        verdicts = _run_verify(lang, invalid_reqs)
        rejected = all(g.get("verdict") == "REJECT" for g in verdicts)
        ok = ok and rejected
        print(f"  {lang}: {'ALL-REJECT' if rejected else 'NOT-REJECTED'}")
        if not rejected:
            for v, got in zip(invalid, verdicts, strict=True):
                if got.get("verdict") != "REJECT":
                    print(f"      {lang} {v['name']}: ACCEPTED (must reject)")
    return ok


def main() -> int:
    vf = json.loads(VECTORS.read_text())
    # The raw 32-byte Ed25519 public key (hex) — a uniform, PEM-free key format
    # every port can load with one call. Derived from the published SPKI PEM.
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    pubkey = load_pem_public_key(vf["public_key_pem"].encode("ascii"))
    pub_hex = pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    valid = vf["vectors"]
    invalid = vf.get("invalid_receipt_vectors", [])

    valid_reqs = [{"jws": v["expected_jws"], "public_key_hex": pub_hex} for v in valid]
    invalid_reqs = [{"jws": v["jws"], "public_key_hex": pub_hex} for v in invalid]

    ran = [name for name, avail in LANGS if avail()]
    print(f"Ports under test: {', '.join(ran)}")

    ok = _verify_valid_receipts(ran, valid, valid_reqs)
    ok = _verify_invalid_receipts(ran, invalid, invalid_reqs) and ok

    if not ok:
        print("\nRESULT: FAIL — a port mis-verified a receipt")
        return 1
    print(
        f"\nRESULT: PASS — verify-rejection proven for: {', '.join(ran)} "
        f"({len(valid)} valid ACCEPT, {len(invalid)} invalid REJECT)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
