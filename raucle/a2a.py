"""Raucle ⇄ A2A binding — verifiable per-skill authorisation for Agent-to-Agent.

Python reference helper for the profile in ``standards/a2a/README.md`` (the
TypeScript sibling is ``reference/a2a-provenance``). A2A lets agents discover and
invoke each other's skills via an **Agent Card** and ``message/send``, but defines
no **per-skill authorisation a third party can verify**. This binding fills that
slot with a signed ``agent_handoff`` provenance receipt — without changing A2A's
wire format, using A2A's own extension + metadata mechanisms.

The receipt is a Compact JWS built with the same header and canonical JSON as the
Raucle provenance receipt, so it is wire-compatible with the other reference
ports. The ``x_a2a_*`` fields are ``x_``-namespaced extensions (provenance spec
§14): ignored by non-A2A verifiers, authoritative for this one.

Flow:

    B (callee) publishes an Agent Card declaring the extension + its issuer
    public key + (optionally) a per-skill capability hash.
    A (caller) emits a signed agent_handoff receipt naming the skill + target,
    attaches it to the A2A Message, and sends.
    B — or any third party, OFFLINE — verifies the receipt against A's published
    key and confirms it authorises this skill on this agent.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

from .provenance import (
    _EXPECTED_ALG,
    _EXPECTED_TYP,
    _b64url_decode,
    _b64url_encode,
    _canonical_json,
    _sha256_hex,
    _utf16_key,
)

RAUCLE_A2A_EXTENSION_URI = "https://raucle.com/spec/a2a/provenance/v1"

_RAUCLE_V1 = "raucle/v1"

#: Sentinel so ``expected_input=None`` (a legitimately empty input) is still
#: bound, distinct from "no input binding requested".
_UNSET = object()


# ── Agent Card declaration ─────────────────────────────────────────────────
def agent_card_extension() -> dict[str, Any]:
    """The ``AgentExtension`` entry an agent lists in its Card to advertise the
    binding."""
    return {
        "uri": RAUCLE_A2A_EXTENSION_URI,
        "description": (
            "Signed provenance receipts + per-skill capability authorisation for inter-agent calls."
        ),
        "version": "1",
        "required": False,
    }


def issuer_public_b64(public_key_pem: bytes) -> str:
    """Export an SPKI PEM Ed25519 public key as the raw-bytes base64 the Agent
    Card publishes (the format a verifier pins)."""
    from cryptography.hazmat.primitives import serialization

    pub = serialization.load_pem_public_key(public_key_pem)
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def card_metadata(
    *,
    iss: str,
    key_id: str,
    public_key_b64: str,
    skill_capabilities: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The Agent Card ``metadata`` entry keyed by the extension URI: the issuer
    public key verifiers pin, plus optional per-skill capability hashes."""
    entry: dict[str, Any] = {
        "receipt_version": "1",
        "issuer": {"iss": iss, "key_id": key_id, "public_key": public_key_b64},
    }
    if skill_capabilities:
        entry["skill_capabilities"] = skill_capabilities
    return {RAUCLE_A2A_EXTENSION_URI: entry}


# ── Emit a hand-off receipt ────────────────────────────────────────────────
def emit_handoff(
    identity: Any,
    *,
    iss: str,
    skill: str,
    target_url: str,
    skill_input: Any,
    parents: list[str],
    issued_at: int,
    capability_proof_hash: str | None = None,
) -> tuple[str, str]:
    """Emit a signed ``agent_handoff`` receipt for an A2A skill call. ``identity``
    is the caller's :class:`~raucle.provenance.AgentIdentity`. ``parents``
    must name at least the caller's task/session-root receipt — ``agent_handoff``
    is a non-root operation, so the provenance verifier (and the other reference
    ports) reject a parentless one. Returns ``(compact_jws, receipt_id)``."""
    if not parents:
        raise ValueError(
            "agent_handoff is a non-root operation: pass the caller's task-root "
            "receipt id in `parents` (a parentless hand-off is not wire-valid)"
        )
    h = _sha256_hex(_canonical_json(skill_input if skill_input is not None else {}))
    payload: dict[str, Any] = {
        "iss": iss,
        "iat": issued_at,
        "agent_id": identity.agent_id,
        "agent_key_id": identity.key_id,
        "operation": "agent_handoff",
        "parents": sorted(parents, key=_utf16_key),
        "input_hash": h,
        "output_hash": h,
        "taint": ["untrusted_user"],
        "x_a2a_skill": skill,
        "x_a2a_target": target_url,
    }
    if capability_proof_hash:
        payload["x_capability_proof_hash"] = capability_proof_hash
    header = {
        "alg": _EXPECTED_ALG,
        "typ": _EXPECTED_TYP,
        "kid": identity.key_id,
        "crit": [_RAUCLE_V1],
        _RAUCLE_V1: "provenance",
    }
    signing_input = (
        _b64url_encode(_canonical_json(header)) + "." + _b64url_encode(_canonical_json(payload))
    ).encode("ascii")
    sig = identity.sign(signing_input)
    jws = signing_input.decode("ascii") + "." + _b64url_encode(sig)
    return jws, "sha256:" + _sha256_hex(jws.encode("ascii"))


def attach_to_message(message: dict[str, Any], receipt_jws: str) -> dict[str, Any]:
    """Attach a hand-off receipt to an outgoing A2A ``Message`` (lists the
    extension URI in ``extensions`` and carries the JWS in ``metadata``)."""
    exts = list(dict.fromkeys([*message.get("extensions", []), RAUCLE_A2A_EXTENSION_URI]))
    metadata = {**message.get("metadata", {}), RAUCLE_A2A_EXTENSION_URI: {"receipt": receipt_jws}}
    return {**message, "extensions": exts, "metadata": metadata}


# ── Verify a received hand-off (offline) ───────────────────────────────────
@dataclass
class HandoffVerdict:
    ok: bool
    reason: str = ""
    skill: str | None = None
    receipt_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)


def _card_meta(card: dict[str, Any]) -> dict[str, Any] | None:
    return (card.get("metadata") or {}).get(RAUCLE_A2A_EXTENSION_URI)


def _verify_jws_signature(
    receipt_jws: str, caller_card: dict[str, Any]
) -> HandoffVerdict | tuple[str, str, str]:
    """Extract the caller key, verify the JWS signature.

    Returns ``(header_b64, payload_b64, sig_b64)`` on success, or a HandoffVerdict on failure.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    meta = _card_meta(caller_card) or {}
    pub_b64 = (meta.get("issuer") or {}).get("public_key")
    if not pub_b64:
        return HandoffVerdict(False, "caller card has no raucle issuer key")

    parts = receipt_jws.split(".")
    if len(parts) != 3:
        return HandoffVerdict(False, "malformed receipt (not a compact JWS)")
    header_b64, payload_b64, sig_b64 = parts
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub.verify(_b64url_decode(sig_b64), signing_input)
    except (InvalidSignature, ValueError):
        return HandoffVerdict(False, "receipt signature did not verify against caller key")
    return header_b64, payload_b64, sig_b64


def _verify_jose_header(header_b64: str) -> HandoffVerdict | dict[str, Any]:
    """Parse and validate the JOSE header. Returns the header dict or a failure verdict."""
    try:
        header = json.loads(_b64url_decode(header_b64))
    except (ValueError, TypeError):
        return HandoffVerdict(False, "receipt header is not valid JSON")
    if _b64url_encode(_canonical_json(header)) != header_b64:
        return HandoffVerdict(False, "receipt header is not canonical JSON")
    if header.get("alg") != _EXPECTED_ALG:
        return HandoffVerdict(False, f"unexpected alg {header.get('alg')!r}")
    if header.get("typ") != _EXPECTED_TYP:
        return HandoffVerdict(False, f"unexpected typ {header.get('typ')!r}")
    if header.get("crit") != [_RAUCLE_V1] or header.get(_RAUCLE_V1) != "provenance":
        return HandoffVerdict(False, "receipt is not a Raucle provenance JWS")
    if set(header) != {"alg", "typ", "kid", "crit", _RAUCLE_V1}:
        return HandoffVerdict(False, "receipt header has unexpected members")
    return header


def _verify_jws_payload(
    payload_b64: str, header: dict[str, Any]
) -> HandoffVerdict | dict[str, Any]:
    """Parse and validate the JWS payload. Returns the payload dict or a failure verdict."""
    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except (ValueError, TypeError):
        return HandoffVerdict(False, "receipt payload is not valid JSON")
    # §6 canonical byte-equality: the on-wire payload MUST be canonical, else a
    # non-canonical / duplicate-key encoding could carry a meaning the signer
    # didn't intend. Reject anything that doesn't re-encode to the same bytes.
    if _b64url_encode(_canonical_json(payload)) != payload_b64:
        return HandoffVerdict(False, "receipt payload is not canonical JSON")
    # The signing key (header.kid) must be the key the payload claims to be from.
    if header.get("kid") != payload.get("agent_key_id"):
        return HandoffVerdict(False, "header kid does not match payload agent_key_id")
    return payload


def _check_replay_and_binding(
    receipt_id: str,
    payload: dict[str, Any],
    seen_receipt_ids: set[str] | None,
    expected_input: Any,
) -> HandoffVerdict | None:
    """Check replay protection and input binding. Returns a failure verdict or None."""
    if seen_receipt_ids is not None:
        # Reserve the id up front (record-before-validate) so there is no
        # check-then-add gap inside this call. For CONCURRENT callees the store
        # must still be externally synchronised — a plain ``set`` is correct only
        # single-threaded; in production back replay-protection with an atomic
        # check-and-insert (e.g. a DB unique constraint on the receipt id).
        if receipt_id in seen_receipt_ids:
            return HandoffVerdict(
                False,
                "receipt has already been seen (replay)",
                receipt_id=receipt_id,
                payload=payload,
            )
        seen_receipt_ids.add(receipt_id)
    if expected_input is not _UNSET:
        want = _sha256_hex(_canonical_json(expected_input if expected_input is not None else {}))
        if payload.get("input_hash") != want:
            return HandoffVerdict(
                False,
                "receipt input_hash does not bind the actual skill input (replay/substitution)",
                receipt_id=receipt_id,
                payload=payload,
            )
    return None


def _verify_handoff_semantics(
    payload: dict[str, Any], callee_card: dict[str, Any], receipt_id: str
) -> HandoffVerdict:
    """Verify operation, target, skill, and capability fields in the payload."""
    if payload.get("operation") != "agent_handoff":
        return HandoffVerdict(
            False,
            f"operation is {payload.get('operation')!r}, expected agent_handoff",
            payload=payload,
            receipt_id=receipt_id,
        )
    # agent_handoff is a non-root operation: a parentless one is not wire-valid,
    # so reject it on the verify side too (not only at emit).
    if not payload.get("parents"):
        return HandoffVerdict(
            False,
            "agent_handoff receipt has no parent (not wire-valid)",
            payload=payload,
            receipt_id=receipt_id,
        )
    callee_url = callee_card.get("url")
    if payload.get("x_a2a_target") != callee_url:
        return HandoffVerdict(
            False,
            f"receipt target {payload.get('x_a2a_target')!r} != this agent {callee_url!r}",
            payload=payload,
            receipt_id=receipt_id,
        )
    skill = payload.get("x_a2a_skill")
    advertised = {s.get("id") for s in callee_card.get("skills", [])}
    if not skill or skill not in advertised:
        return HandoffVerdict(
            False,
            f"skill {skill!r} is not advertised by this agent",
            payload=payload,
            receipt_id=receipt_id,
        )
    required_cap = ((_card_meta(callee_card) or {}).get("skill_capabilities") or {}).get(skill)
    if required_cap and payload.get("x_capability_proof_hash") != required_cap:
        return HandoffVerdict(
            False,
            f"skill {skill!r} requires capability {required_cap}; receipt does not cite it",
            payload=payload,
            receipt_id=receipt_id,
        )
    return HandoffVerdict(True, "", skill=skill, receipt_id=receipt_id, payload=payload)


def verify_handoff(
    receipt_jws: str,
    caller_card: dict[str, Any],
    callee_card: dict[str, Any],
    *,
    expected_input: Any = _UNSET,
    seen_receipt_ids: set[str] | None = None,
) -> HandoffVerdict:
    """Verify a hand-off receipt **offline** against the *caller's* published key
    and confirm it authorises this call on *this* (callee) card. No network.

    Checks: caller key present → JOSE header is canonical with the expected
    ``alg``/``typ``/``crit``/``raucle/v1`` and ``kid`` bound to ``agent_key_id`` →
    signature valid → payload is canonical (§6) → ``operation == agent_handoff`` →
    target matches this agent's URL → skill is advertised → if the callee binds
    the skill to a capability hash, the receipt must cite it.

    Binding the call (anti-replay / anti-substitution): pass ``expected_input`` —
    the exact skill input this callee is about to execute — and the receipt's
    ``input_hash`` must match it, so a receipt signed for one call cannot be
    replayed against a different input. For replay of the *same* input, pass a
    ``seen_receipt_ids`` set the callee persists; a receipt id seen before is
    rejected (idempotency). A caller-key swap is out of scope: ``caller_card``
    must be authenticated/pinned out of band (A2A discovery), which this helper
    assumes — it cannot detect a forged card.
    """
    # Step 1: verify caller key + JWS signature
    sig_result = _verify_jws_signature(receipt_jws, caller_card)
    if isinstance(sig_result, HandoffVerdict):
        return sig_result
    header_b64, payload_b64, _sig_b64 = sig_result

    # Step 2: validate JOSE header
    header_result = _verify_jose_header(header_b64)
    if isinstance(header_result, HandoffVerdict):
        return header_result
    header = header_result

    # Step 3: validate payload
    payload_result = _verify_jws_payload(payload_b64, header)
    if isinstance(payload_result, HandoffVerdict):
        return payload_result
    payload = payload_result

    # Step 4: replay protection and input binding
    receipt_id = "sha256:" + _sha256_hex(receipt_jws.encode("ascii"))
    replay_error = _check_replay_and_binding(receipt_id, payload, seen_receipt_ids, expected_input)
    if replay_error is not None:
        return replay_error

    # Step 5: verify handoff semantics (operation, target, skill, capability)
    return _verify_handoff_semantics(payload, callee_card, receipt_id)
