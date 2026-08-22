"""Agent Trust Registry — the cross-organisation trust-anchor layer (P1).

A capability token or provenance receipt is only as trustworthy as the verifier's
ability to map its ``key_id`` to a public key it trusts. Today that mapping is
either hardcoded (``CapabilityGate(trusted_issuers={key_id: pem})``) or pinned
out of band (A2A cards). Neither scales across organisations: an agent in org B
cannot verify an agent in org A's receipt without already holding A's key.

The **Trust Registry** is the shared, resolvable, tamper-evident directory that
closes this gap — the certificate-transparency analogue for agent issuers. An
issuer *publishes* its public key once; any verifier in any org *resolves*
``key_id -> public key`` from the registry and checks revocation. Each new
publisher makes the next verification easier: the network effect that turns
raucle from a per-org library into ecosystem infrastructure.

Design (mirrors the proven append-only signed chain in ``audit.py``):

- The registry is an **append-only JSONL log**. Each line is an entry:
  a ``register`` (issuer + public key + metadata) or a ``revoke`` (key_id).
  Nothing is ever mutated; revocation is a new entry, so history is auditable.
- Entries are **hash-chained** (each carries the previous entry's hash), so a
  consumer detects tampering or reordering.
- The registry **operator signs** the head, so a consumer who trusts the
  operator key can trust the whole log with one signature check
  (transparency-log style). An unsigned registry is usable but only
  integrity-checked (chain), not authenticated.

Fail-closed: ``public_key(key_id)`` returns ``None`` for an unknown **or revoked**
key, so a verifier built on the registry denies by default.

CLI: ``raucle registry init|publish|revoke|list|resolve``.
Client for the hosted service: :meth:`TrustRegistry.from_url` fetches a published
registry over HTTPS (SSRF-guarded) and verifies it before use.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raucle._canon import make_duplicate_key_rejecter
from raucle.audit import (
    Ed25519Signer,
    _canonical_json,
    _sha256_hex,
)

#: Reject duplicate JSON keys in registry entries — a crafted entry with
#: duplicate keys (e.g. {"key_id":"a","key_id":"b"}) would be silently accepted
#: by json.loads (keeping the last value), potentially smuggling a different
#: key_id past integrity checks. Consistent with audit.py and provenance.py.
_reject_duplicate_keys = make_duplicate_key_rejecter("trust registry entry (JSON ambiguity)")

logger = logging.getLogger(__name__)

#: Registry format version, stamped on the header entry.
REGISTRY_VERSION = "trust-registry/v1"

_GENESIS = "0" * 64

#: Allowed forward clock skew when checking head freshness (codex r8): a head
#: timestamped further in the future than this is rejected as forged/invalid.
_MAX_CLOCK_SKEW_SECONDS = 300


def _now() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())


def _canon_issuer(name: str) -> str:
    """Canonical form of an issuer name for uniqueness comparison: NFC-normalised,
    case-folded, stripped. So "Acme Bank" and "acme bank " cannot both be active
    (confusable-name impersonation)."""
    import unicodedata

    return unicodedata.normalize("NFC", str(name)).casefold().strip()


def _key_id_for(public_key_pem: bytes | str) -> str:
    """The canonical ``key_id`` for a public key: first 16 hex of SHA-256 over
    the PEM (matches ``CapabilityIssuer.key_id`` / cap:v1)."""
    pem = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
    return _sha256_hex(pem)[:16]


@dataclass
class TrustRecord:
    """The resolved state of an issuer in the registry."""

    key_id: str
    public_key_pem: str
    issuer: str
    created_at: int
    revoked: bool = False
    revoked_reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "issuer": self.issuer,
            "created_at": self.created_at,
            "revoked": self.revoked,
        }
        if self.revoked_reason:
            d["revoked_reason"] = self.revoked_reason
        if self.metadata:
            d["metadata"] = self.metadata
        return d


class RegistryIntegrityError(Exception):
    """Raised when a registry's hash chain or operator signature does not verify."""


class TrustRegistry:
    """An append-only, hash-chained, optionally operator-signed trust directory.

    Parameters
    ----------
    path : str | Path | None
        Backing JSONL file. ``None`` for an in-memory registry (tests / transient).
    operator_signer : Ed25519Signer | None
        If given, the registry is authenticated: a signed head entry is appended
        and consumers can verify the whole log against the operator public key.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        operator_signer: Ed25519Signer | None = None,
    ) -> None:
        self._path = Path(path) if path is not None else None
        self._signer = operator_signer
        self._entries: list[dict[str, Any]] = []
        self._tail_hash = _GENESIS
        self._authenticated: bool | None = None
        if self._path is not None and self._path.exists():
            self._load_existing()
        elif not self._entries:
            self._append_header()

    # -- construction / loading ---------------------------------------------

    def _append_header(self) -> None:
        header: dict[str, Any] = {
            "type": "header",
            "version": REGISTRY_VERSION,
            "signed": self._signer is not None,
        }
        if self._signer is not None:
            header["operator_key_id"] = _key_id_for(self._signer.public_key_pem())
        self._write_entry(header)

    def _load_existing(self) -> None:
        assert self._path is not None
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            self._entries.append(json.loads(line, object_pairs_hook=_reject_duplicate_keys))
        if not self._entries:
            self._append_header()
            return
        # Recompute the tail hash from the on-disk records.
        self._tail_hash = self._entries[-1].get("hash", _GENESIS)

    @classmethod
    def load(cls, path: str | Path) -> TrustRegistry:
        """Load and integrity-check a registry from disk."""
        reg = cls(path)
        reg.verify_integrity()
        return reg

    @classmethod
    def from_jsonl(cls, text: str) -> TrustRegistry:
        """Build an in-memory registry from JSONL text and integrity-check it."""
        reg = cls()
        reg._entries = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                reg._entries.append(json.loads(line))
        if not reg._entries:
            reg._append_header()
        else:
            reg._tail_hash = reg._entries[-1].get("hash", _GENESIS)
        reg.verify_integrity()
        return reg

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        operator_public_pem: bytes | None = None,
        allow_unauthenticated: bool = False,
        min_index: int | None = None,
        expected_head_hash: str | None = None,
        max_age_seconds: int | None = None,
        timeout: float = 10.0,
    ) -> TrustRegistry:
        """Fetch a published registry over HTTPS (SSRF-guarded) and verify it.

        A registry fetched from a URL is attacker-controllable: a forger can serve
        a self-consistent signed log full of their own issuer keys. So by default
        this **requires authentication** — pass ``operator_public_pem`` to pin the
        operator key. Loading WITHOUT authentication (an unsigned registry, or a
        signed one with no pinned key) is refused unless you explicitly pass
        ``allow_unauthenticated=True`` (e.g. for a registry you already trust by
        transport). The bare integrity check (hash chain) does not authenticate
        the source and is not a substitute (codex #1).
        """
        from raucle.feed import fetch_https_pinned

        body = fetch_https_pinned(url, timeout=timeout).decode("utf-8")
        reg = cls()
        reg._entries = []
        for line in body.splitlines():
            line = line.strip()
            if line:
                reg._entries.append(json.loads(line))
        if not reg._entries:
            reg._append_header()
        else:
            reg._tail_hash = reg._entries[-1].get("hash", _GENESIS)
        reg.verify_integrity(
            operator_public_pem=operator_public_pem,
            min_index=min_index,
            expected_head_hash=expected_head_hash,
            max_age_seconds=max_age_seconds,
        )
        if reg._authenticated is not True and not allow_unauthenticated:
            raise RegistryIntegrityError(
                f"refusing to trust trust-registry fetched from {url}: not authenticated. "
                "Pass operator_public_pem to pin the operator key, or "
                "allow_unauthenticated=True only if you trust the transport."
            )
        return reg

    # -- writing -------------------------------------------------------------

    def _write_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        entry = dict(entry)
        entry["index"] = len(self._entries)
        entry["prev_hash"] = self._tail_hash
        entry.setdefault("ts", _now())  # signed freshness anchor (codex r7)
        # Hash covers everything except the hash field and the operator signature.
        body = {k: v for k, v in entry.items() if k not in ("hash", "operator_sig")}
        entry_hash = _sha256_hex(_canonical_json(body))
        entry["hash"] = entry_hash
        if self._signer is not None:
            entry["operator_sig"] = _b64(self._signer.sign(entry_hash.encode("ascii")))
        self._entries.append(entry)
        self._tail_hash = entry_hash
        if self._path is not None:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
        return entry

    def publish(
        self,
        public_key_pem: bytes | str,
        *,
        issuer: str,
        metadata: dict[str, Any] | None = None,
        created_at: int = 0,
    ) -> str:
        """Register an issuer public key. Returns its ``key_id``.

        Re-publishing a previously-revoked key reactivates it (a fresh
        ``register`` entry supersedes the revocation, auditable in history).
        """
        pem = public_key_pem.decode() if isinstance(public_key_pem, bytes) else public_key_pem
        key_id = _key_id_for(pem)
        # Issuer NAME uniqueness (codex re-review #3): the issuer string is the
        # authoritative identity verifiers match against, so the operator must not
        # let two different keys hold the same active issuer name (confusable-name
        # impersonation). Re-publishing the SAME key under its name is fine.
        canon = _canon_issuer(issuer)
        if not canon:
            raise ValueError("issuer name must be non-empty")
        for kid, rec in self._fold().items():
            if not rec.revoked and _canon_issuer(rec.issuer) == canon and kid != key_id:
                raise ValueError(
                    f"issuer name {issuer!r} collides with an active key ({kid}, "
                    f"issuer {rec.issuer!r}); revoke it first, or use a distinct issuer identity"
                )
        self._write_entry(
            {
                "type": "register",
                "key_id": key_id,
                "public_key_pem": pem,
                "issuer": issuer,
                "created_at": int(created_at),
                "metadata": metadata or {},
            }
        )
        return key_id

    def revoke(self, key_id: str, *, reason: str = "") -> None:
        """Revoke an issuer key. Append-only; history is preserved."""
        self._write_entry({"type": "revoke", "key_id": key_id, "reason": reason})

    # -- resolution (the consumer surface) ----------------------------------

    def _fold(self) -> dict[str, TrustRecord]:
        """Replay the log into current per-key state (last entry wins)."""
        state: dict[str, TrustRecord] = {}
        for e in self._entries:
            t = e.get("type")
            if t == "register":
                state[e["key_id"]] = TrustRecord(
                    key_id=e["key_id"],
                    public_key_pem=e["public_key_pem"],
                    issuer=e.get("issuer", ""),
                    created_at=int(e.get("created_at", 0)),
                    revoked=False,
                    metadata=e.get("metadata") or {},
                )
            elif t == "revoke":
                rec = state.get(e["key_id"])
                if rec is not None:
                    rec.revoked = True
                    rec.revoked_reason = e.get("reason", "")
        return state

    def resolve(self, key_id: str) -> TrustRecord | None:
        """Return the full record for ``key_id`` (including revoked ones), or None."""
        return self._fold().get(key_id)

    def public_key(self, key_id: str) -> str | None:
        """Resolve ``key_id`` to a public-key PEM, **fail-closed**: returns None
        for an unknown OR revoked key."""
        rec = self._fold().get(key_id)
        if rec is None or rec.revoked:
            return None
        return rec.public_key_pem

    def is_revoked(self, key_id: str) -> bool:
        rec = self._fold().get(key_id)
        return rec is not None and rec.revoked

    def as_issuer_map(self) -> dict[str, str]:
        """``{key_id: pem}`` for all **active** issuers — drop-in for
        ``CapabilityGate(trusted_issuers=...)``."""
        return {kid: rec.public_key_pem for kid, rec in self._fold().items() if not rec.revoked}

    def records(self) -> list[TrustRecord]:
        return list(self._fold().values())

    def head(self) -> dict[str, Any]:
        """The current signed head: ``{index, hash, ts}``. A consumer records this
        from a trusted/fresh source and later pins it (``expected_head_hash`` /
        ``min_index`` / ``max_age_seconds``) to detect a stale snapshot that omits
        a later revocation (codex r7)."""
        last = self._entries[-1] if self._entries else {}
        return {
            "index": last.get("index", -1),
            "hash": last.get("hash", _GENESIS),
            "ts": last.get("ts", 0),
        }

    # -- integrity -----------------------------------------------------------

    def verify_integrity(
        self,
        *,
        operator_public_pem: bytes | None = None,
        min_index: int | None = None,
        expected_head_hash: str | None = None,
        max_age_seconds: int | None = None,
        now: int | None = None,
    ) -> bool:
        """Verify the hash chain and (if signed) the operator signatures.

        Raises :class:`RegistryIntegrityError` on any break. ``operator_public_pem``
        pins the expected operator key; if omitted, signatures are verified against
        the key declared in the header (integrity, not external authentication).
        """
        prev = _GENESIS
        op_pub = None
        for i, e in enumerate(self._entries):
            if e.get("index") != i:
                raise RegistryIntegrityError(f"entry {i}: index mismatch")
            if e.get("prev_hash") != prev:
                raise RegistryIntegrityError(f"entry {i}: broken chain")
            body = {k: v for k, v in e.items() if k not in ("hash", "operator_sig")}
            expect = _sha256_hex(_canonical_json(body))
            if e.get("hash") != expect:
                raise RegistryIntegrityError(f"entry {i}: hash mismatch (tampered)")
            # Resolution security depends on key_id being the real digest of the
            # published PEM — otherwise a forged entry could map a victim key_id
            # to an attacker key. Enforce the invariant (codex #6).
            if e.get("type") == "register":
                pem = e.get("public_key_pem", "")
                if e.get("key_id") != _key_id_for(pem):
                    raise RegistryIntegrityError(
                        f"entry {i}: key_id does not match SHA-256 of its public key"
                    )
            prev = e["hash"]

        # Enforce active issuer-name uniqueness on load — publish() alone does not
        # protect a hand-crafted (even operator-signed) registry file (codex r3 #1).
        seen_names: dict[str, str] = {}
        for kid, rec in self._fold().items():
            if rec.revoked:
                continue
            canon = _canon_issuer(rec.issuer)
            if not canon:
                raise RegistryIntegrityError(
                    f"active register entry for key {kid} has a blank issuer name"
                )
            if canon in seen_names and seen_names[canon] != kid:
                raise RegistryIntegrityError(
                    f"duplicate active issuer name {rec.issuer!r} "
                    f"(keys {seen_names[canon]} and {kid})"
                )
            seen_names[canon] = kid

        header = self._entries[0] if self._entries else {}
        if header.get("signed"):
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            pem = operator_public_pem
            if pem is None and self._signer is not None:
                pem = self._signer.public_key_pem()
            if pem is None:
                # Chain integrity is verified (tamper-evidence within the log),
                # but without the operator key we have NOT authenticated the log —
                # a forger who rebuilt the whole chain would pass. That is a valid
                # choice for a local, trusted file (load() does this quietly); the
                # risky case (untrusted network source) is warned in from_url().
                # Do NOT return here: the freshness checks below must still run
                # (codex r8) — a rollback can be detected even unauthenticated.
                self._authenticated = False
            else:
                self._authenticated = True
                loaded = serialization.load_pem_public_key(pem)
                if not isinstance(loaded, Ed25519PublicKey):
                    raise RegistryIntegrityError("operator key is not Ed25519")
                op_pub = loaded
                for i, e in enumerate(self._entries):
                    sig = e.get("operator_sig")
                    if not sig:
                        raise RegistryIntegrityError(f"entry {i}: missing operator signature")
                    try:
                        op_pub.verify(_b64d(sig), e["hash"].encode("ascii"))
                    except (InvalidSignature, ValueError) as exc:
                        raise RegistryIntegrityError(
                            f"entry {i}: operator signature invalid"
                        ) from exc

        # Freshness anchor (codex r7): a chain-valid, fully operator-signed
        # snapshot is still vulnerable to a *rollback* — an attacker serves an
        # older signed prefix that omits a later revocation. The consumer pins
        # what it knows the head should be (index/hash) or a max age, and any
        # snapshot that falls short is rejected as stale.
        head = self.head()
        if min_index is not None and head["index"] < min_index:
            raise RegistryIntegrityError(
                f"stale snapshot: head index {head['index']} < expected min {min_index}"
            )
        if expected_head_hash is not None and head["hash"] != expected_head_hash:
            raise RegistryIntegrityError(
                f"stale snapshot: head hash {head['hash']} != expected {expected_head_hash}"
            )
        if max_age_seconds is not None:
            ref = now if now is not None else _now()
            try:
                head_ts = int(head["ts"])
            except (TypeError, ValueError) as exc:
                raise RegistryIntegrityError("head ts is not an integer timestamp") from exc
            # A future-dated head would make ref - ts negative and stay "fresh"
            # forever — reject it beyond a small clock-skew allowance (codex r8).
            if head_ts > ref + _MAX_CLOCK_SKEW_SECONDS:
                raise RegistryIntegrityError(
                    f"stale/forged snapshot: head ts {head_ts} is in the future "
                    f"(now {ref}, allowed skew {_MAX_CLOCK_SKEW_SECONDS}s)"
                )
            if ref - head_ts > max_age_seconds:
                raise RegistryIntegrityError(
                    f"stale snapshot: head is {ref - head_ts}s old (max {max_age_seconds}s)"
                )
        return True


# Local copies of the b64url helpers (audit uses identical ones internally).
import base64 as _base64  # noqa: E402


def _b64(data: bytes) -> str:
    return _base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return _base64.urlsafe_b64decode(data + padding)


__all__ = [
    "REGISTRY_VERSION",
    "TrustRecord",
    "TrustRegistry",
    "RegistryIntegrityError",
]
