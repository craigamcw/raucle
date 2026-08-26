"""Signed verdict receipts — downstream-verifiable proof that a scan happened.

Every scan result can be issued as a detached JWS (JSON Web Signature) token
containing a hash of the input, a hash of the active ruleset, the verdict,
and an ISO timestamp.  Downstream systems (SIEMs, audit dashboards, gateway
sidecars) can verify these receipts against the issuer's public key without
trusting transport logs.

This is the LLM-guardrail analogue of Sigstore for artifacts: a cryptographic
chain-of-custody for security decisions.

Usage::

    from raucle import Scanner
    from raucle.verdicts import VerdictSigner

    signer = VerdictSigner.generate()
    scanner = Scanner(verdict_signer=signer)
    result = scanner.scan("Ignore all previous instructions")
    print(result.receipt)   # compact JWS string

    # Verify downstream
    from raucle.verdicts import VerdictVerifier
    v = VerdictVerifier(public_key_pem=signer.public_key_pem())
    payload = v.verify(result.receipt, expected_input="Ignore all previous instructions")
    print(payload["verdict"], payload["confidence"])

Why JWS and not JWT?
--------------------
We use compact JWS with ``alg=EdDSA`` (Ed25519) and a JSON payload that mirrors
JWT claim conventions, but we deliberately do not call it a JWT — these are
not bearer tokens, they are signed receipts.  ``crit=raucle/v1`` prevents
generic JWT libraries from silently accepting them as auth tokens.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

from ._canon import utf16_key as _u16  # UTF-16 ordering for signed value lists

_RAUCLE_V1 = "raucle/v1"
logger = logging.getLogger(__name__)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _canonical_json(obj: Any) -> bytes:
    from ._canon import reorder_keys_utf16  # UTF-16 key ordering (shared)

    return json.dumps(
        reorder_keys_utf16(obj), sort_keys=False, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_input(text: str) -> str:
    """Hash an input prompt for inclusion in a receipt."""
    return _sha256_hex(text.encode("utf-8"))


def hash_ruleset(rules: list[dict[str, Any]]) -> str:
    """Hash the active ruleset for inclusion in a receipt.

    Uses a canonical projection of (id, score, patterns) so reordering rules
    or changing irrelevant metadata does not invalidate prior receipts.
    """
    projection = sorted(
        [
            {
                "id": r.get("id", ""),
                "score": r.get("score", 0.0),
                "patterns": sorted(r.get("patterns", []), key=_u16),
            }
            for r in rules
        ],
        key=lambda r: _u16(r["id"]),
    )
    return _sha256_hex(_canonical_json(projection))


# ---------------------------------------------------------------------------
# Signer
# ---------------------------------------------------------------------------


class VerdictSigner:
    """Ed25519-based signer for verdict receipts.

    The same key can be reused for the audit-chain :class:`Ed25519Signer`;
    this class is a thin specialisation that emits compact JWS strings.
    """

    def __init__(self, private_key: Any) -> None:
        self._private_key = private_key
        try:
            from cryptography.hazmat.primitives import serialization

            self._public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception as exc:
            # Fail loud — a signer that cannot expose its public key
            # cannot produce verifiable receipts. Surface, don't swallow.
            from raucle.errors import ConfigurationError

            logger.exception("VerdictSigner: failed to extract public key bytes: %s", exc)
            raise ConfigurationError(
                f"VerdictSigner: failed to extract public key bytes: {exc}"
            ) from exc

    @classmethod
    def generate(cls) -> VerdictSigner:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem_bytes: bytes, password: bytes | None = None) -> VerdictSigner:
        from cryptography.hazmat.primitives import serialization

        return cls(serialization.load_pem_private_key(pem_bytes, password=password))

    def public_key_pem(self) -> bytes:
        return self._public_pem

    def key_id(self) -> str:
        # ``_public_pem`` is always populated post-``__init__`` — a
        # missing public key now raises ``ConfigurationError`` at
        # construction rather than silently producing an "unsigned"
        # key id (which generates unverifiable receipts).
        return hashlib.sha256(self._public_pem).hexdigest()[:16]

    def issue(
        self,
        *,
        input_text: str,
        verdict: str,
        confidence: float,
        ruleset_hash: str,
        model_version: str = "",
        tenant: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        """Issue a compact JWS receipt for a scan verdict.

        Returns
        -------
        str
            Compact JWS in the form ``base64url(header).base64url(payload).base64url(sig)``.
        """
        header = {
            "alg": "EdDSA",
            "typ": "raucle-receipt/v1",
            "kid": self.key_id(),
            "crit": [_RAUCLE_V1],
            _RAUCLE_V1: "verdict",
        }
        payload: dict[str, Any] = {
            "iss": "raucle",
            "iat": int(dt.datetime.now(dt.timezone.utc).timestamp()),
            "input_hash": hash_input(input_text),
            "verdict": verdict,
            "confidence": round(confidence, 4),
            "ruleset_hash": ruleset_hash,
            "model_version": model_version,
        }
        if tenant is not None:
            payload["tenant"] = tenant
        if extra:
            payload["extra"] = extra

        signing_input = (
            _b64url_encode(_canonical_json(header)) + "." + _b64url_encode(_canonical_json(payload))
        ).encode("ascii")
        sig = self._private_key.sign(signing_input)
        return signing_input.decode("ascii") + "." + _b64url_encode(sig)


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


@dataclass
class ReceiptPayload:
    """Decoded receipt contents."""

    issuer: str
    issued_at: int
    input_hash: str
    verdict: str
    confidence: float
    ruleset_hash: str
    model_version: str
    tenant: str | None = None
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "iss": self.issuer,
            "iat": self.issued_at,
            "input_hash": self.input_hash,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "ruleset_hash": self.ruleset_hash,
            "model_version": self.model_version,
        }
        if self.tenant is not None:
            out["tenant"] = self.tenant
        if self.extra is not None:
            out["extra"] = self.extra
        return out


class VerdictVerificationError(Exception):
    """Raised when a receipt fails verification."""


class VerdictVerifier:
    """Verify compact JWS verdict receipts.

    Parameters
    ----------
    public_key_pem : bytes
        Ed25519 public key in PEM format.
    """

    def __init__(self, public_key_pem: bytes) -> None:
        from cryptography.hazmat.primitives import serialization

        self._public_key = serialization.load_pem_public_key(public_key_pem)
        self._key_id = hashlib.sha256(public_key_pem).hexdigest()[:16]

    def verify(
        self,
        receipt: str,
        *,
        expected_input: str | None = None,
        expected_ruleset_hash: str | None = None,
        max_age_seconds: int | None = None,
    ) -> ReceiptPayload:
        """Verify a receipt and return its payload.

        Raises :class:`VerdictVerificationError` on any failure.
        """
        try:
            header_b64, payload_b64, sig_b64 = receipt.split(".")
        except ValueError as exc:
            raise VerdictVerificationError("malformed receipt — expected three segments") from exc

        try:
            header = json.loads(_b64url_decode(header_b64))
            payload = json.loads(_b64url_decode(payload_b64))
            sig = _b64url_decode(sig_b64)
        except Exception as exc:
            raise VerdictVerificationError(f"failed to decode receipt: {exc}") from exc

        # Header sanity
        if header.get("alg") != "EdDSA":
            raise VerdictVerificationError(f"unexpected alg: {header.get('alg')!r}")
        if header.get("typ") != "raucle-receipt/v1":
            raise VerdictVerificationError(f"unexpected typ: {header.get('typ')!r}")
        crit = header.get("crit") or []
        if _RAUCLE_V1 not in crit:
            raise VerdictVerificationError("crit must include 'raucle/v1'")

        # Signature
        signing_input = (header_b64 + "." + payload_b64).encode("ascii")
        try:
            self._public_key.verify(sig, signing_input)
        except Exception as exc:
            raise VerdictVerificationError(f"signature verification failed: {exc}") from exc

        # Bindings
        if expected_input is not None and payload.get("input_hash") != hash_input(expected_input):
            raise VerdictVerificationError("input_hash does not match expected input")
        if (
            expected_ruleset_hash is not None
            and payload.get("ruleset_hash") != expected_ruleset_hash
        ):
            raise VerdictVerificationError("ruleset_hash does not match expected ruleset")
        if max_age_seconds is not None:
            now = int(dt.datetime.now(dt.timezone.utc).timestamp())
            iat = payload.get("iat", 0)
            if now - iat > max_age_seconds:
                raise VerdictVerificationError(
                    f"receipt is {now - iat}s old, exceeds max_age {max_age_seconds}s"
                )

        return ReceiptPayload(
            issuer=payload.get("iss", ""),
            issued_at=payload.get("iat", 0),
            input_hash=payload.get("input_hash", ""),
            verdict=payload.get("verdict", ""),
            confidence=payload.get("confidence", 0.0),
            ruleset_hash=payload.get("ruleset_hash", ""),
            model_version=payload.get("model_version", ""),
            tenant=payload.get("tenant"),
            extra=payload.get("extra"),
        )
