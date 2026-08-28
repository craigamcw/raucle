#!/usr/bin/env python3
"""Generate canonical test vectors for the Raucle Provenance Receipt v1 spec.

Reads a deterministic seed corpus and emits a JSON file mapping vector name
to ``(input, expected_jws, expected_receipt_hash)``. Implementations claiming
v1 conformance MUST reproduce every vector byte-for-byte.

Usage::

    python scripts/gen_provenance_test_vectors.py > docs/spec/provenance/v1/test-vectors.json
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Deterministic Ed25519 seed — same bytes => same keys => same signatures.
# Anyone re-running this script gets identical output, including signatures.
_FIXED_SEED = bytes.fromhex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")


def _build_identity():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from raucle.provenance import CapabilityStatement, _sha256_hex

    priv = Ed25519PrivateKey.from_private_bytes(_FIXED_SEED)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = _sha256_hex(pub_pem)[:16]
    stmt = CapabilityStatement(
        agent_id="agent:test-vectors",
        key_id=key_id,
        public_key_pem=pub_pem.decode("ascii"),
        allowed_models=["test-model-v1"],
        allowed_tools=["test-tool"],
        issuer="raucle",
        issued_at=1_700_000_000,
        expires_at=None,
    )
    # Self-sign the statement deterministically
    from raucle.provenance import _canonical_json

    sig = priv.sign(_canonical_json(stmt.body()))
    stmt.signature = base64.b64encode(sig).decode("ascii")

    # Wrap as AgentIdentity without going through generate() (random key)
    from raucle.provenance import AgentIdentity

    return AgentIdentity(agent_id="agent:test-vectors", private_key=priv, statement=stmt)


def _build_vectors() -> dict:
    from raucle.provenance import Operation, ProvenanceReceipt, hash_obj, hash_text

    identity = _build_identity()
    vectors: dict = {
        "spec_version": "raucle-provenance-receipt/v1",
        # Frozen historical label — part of the committed vector artifact,
        # non-normative (pre-dates the raucle-detect -> raucle rename).
        "generator_version": "raucle-detect 0.5.0",
        "fixed_seed_hex": _FIXED_SEED.hex(),
        "agent_id": identity.agent_id,
        "agent_key_id": identity.key_id,
        "public_key_pem": identity.statement.public_key_pem,
        "vectors": [],
    }

    # Vector 1: minimal user_input root
    r1 = ProvenanceReceipt(
        agent_id=identity.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.USER_INPUT,
        input_hash=hash_text("Hello, world."),
        taint=["external_user"],
        issued_at=1_700_000_001,
    )
    r1.sign(identity)
    vectors["vectors"].append(
        {
            "name": "user_input_minimal",
            "description": "Minimal root receipt for a user_input operation",
            "expected_jws": r1.jws,
            "expected_receipt_hash": r1.receipt_hash,
        }
    )

    # Vector 2: model_call descending from vector 1
    r2 = ProvenanceReceipt(
        agent_id=identity.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.MODEL_CALL,
        parents=[r1.receipt_hash],
        model="test-model-v1",
        input_hash=hash_text("Hello, world."),
        output_hash=hash_text("Greetings."),
        taint=["external_user"],
        issued_at=1_700_000_002,
    )
    r2.sign(identity)
    vectors["vectors"].append(
        {
            "name": "model_call_inheriting_taint",
            "description": "model_call citing the user_input as parent; inherits taint",
            "expected_jws": r2.jws,
            "expected_receipt_hash": r2.receipt_hash,
        }
    )

    # Vector 3: tool_call with structured args/output
    r3 = ProvenanceReceipt(
        agent_id=identity.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.TOOL_CALL,
        parents=[r2.receipt_hash],
        tool="test-tool",
        input_hash=hash_obj({"argument": 42}),
        output_hash=hash_obj({"result": True}),
        taint=["external_user"],
        issued_at=1_700_000_003,
    )
    r3.sign(identity)
    vectors["vectors"].append(
        {
            "name": "tool_call_with_structured_args",
            "description": "tool_call hashing structured input args and output objects",
            "expected_jws": r3.jws,
            "expected_receipt_hash": r3.receipt_hash,
        }
    )

    # Vector 4: sanitisation removing a taint tag
    r4 = ProvenanceReceipt(
        agent_id=identity.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.SANITISATION,
        parents=[r3.receipt_hash],
        tool="redactor:pii-v1",
        corpus="removed:external_user",
        input_hash=hash_text("Greetings."),
        output_hash=hash_text("[REDACTED]"),
        taint=[],  # external_user removed
        issued_at=1_700_000_004,
    )
    r4.sign(identity)
    vectors["vectors"].append(
        {
            "name": "sanitisation_removes_tag",
            "description": "sanitisation operation explicitly removing the external_user taint",
            "expected_jws": r4.jws,
            "expected_receipt_hash": r4.receipt_hash,
        }
    )

    # Vector 5: guardrail_scan with verdict
    r5 = ProvenanceReceipt(
        agent_id=identity.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.GUARDRAIL_SCAN,
        parents=[r1.receipt_hash],
        input_hash=hash_text("Hello, world."),
        ruleset_hash="sha256:" + "0" * 64,
        guardrail_verdict="CLEAN",
        taint=["external_user", "guardrail-scan:input"],
        issued_at=1_700_000_005,
    )
    r5.sign(identity)
    vectors["vectors"].append(
        {
            "name": "guardrail_scan_clean",
            "description": "guardrail_scan emitting a CLEAN verdict with ruleset hash",
            "expected_jws": r5.jws,
            "expected_receipt_hash": r5.receipt_hash,
        }
    )

    return vectors


def _canonicalization_vectors() -> list[dict]:
    """Pure JCS + SHA-256 vectors over EXPOSED preimage objects, so a peer
    implementation can byte-diff §4 canonicalisation directly (interop, e.g. the
    A2A/APS action_ref preimage) without reverse-engineering a receipt body.

    Each vector exposes the input object, the canonical UTF-8 JCS string, and its
    SHA-256 hex. Uses the SAME `_canonical_json` (§4.3 restricted subset) the
    receipts use.
    """
    import unicodedata

    from raucle.provenance import _canonical_json, _sha256_hex

    def vec(name: str, desc: str, obj: dict) -> dict:
        jcs = _canonical_json(obj)  # bytes, §4.3 canonical form
        return {
            "name": name,
            "description": desc,
            "input_object": obj,
            "expected_canonical_utf8": jcs.decode("utf-8"),
            # Unambiguous byte artifact: hex of the exact UTF-8 canonical bytes,
            # so a peer can byte-diff without depending on how the outer JSON
            # escapes non-ASCII (the file itself uses ensure_ascii=True).
            "expected_canonical_hex": jcs.hex(),
            "expected_canonical_sha256": "sha256:" + _sha256_hex(jcs),
        }

    # APS action_ref preimage shape: 4 fields, all strings / arrays of strings.
    # scopeRequired pre-sorted by Unicode code point and NFC-normalised per the
    # action_ref definition (that ordering is a producer step, not JCS).
    scopes = sorted(unicodedata.normalize("NFC", s) for s in ["commerce.read", "commerce.write"])
    action_ref = {
        "actionType": "commerce_preflight",
        "agentId": "did:aps:z6MkExampleAgentIdInCanonicalMultibaseForm",
        "scopeRequired": scopes,
        "timestamp": "2026-04-08T12:00:00Z",
    }

    return [
        vec(
            "canon_action_ref_aps",
            "APS §4.1 action_ref preimage (4 string/array-of-string fields; no numbers, "
            "so the ±(2^53-1) integer bound is moot — restricted subset == full RFC 8785 here)",
            action_ref,
        ),
        vec(
            "canon_non_ascii_strings",
            "Non-ASCII strings MUST be raw UTF-8, never \\uXXXX-escaped (§4.3.4). "
            "Mix of Latin-1, CJK, and emoji to exercise multi-byte UTF-8.",
            {"corpus": "café — naïve — 日本語 — 🔒", "taint": ["external_user", "naïveté"]},
        ),
        vec(
            "canon_non_nfc_passthrough",
            "Canonicalisation is pure serialisation (RFC 8785) and does NOT apply "
            "Unicode normalisation: a decomposed string is emitted byte-for-byte as "
            "given, NOT folded to NFC. The value is U+0041 U+030A (LATIN A + COMBINING "
            "RING) — distinct bytes from the precomposed U+00C5 'Å'. Interop note: NFC "
            "is a *producer* responsibility (e.g. APS sorts/normalises scopeRequired "
            "before canonicalising); a canonicaliser that silently NFC-folds here would "
            "diverge on this input.",
            {"scope": "A\u030a"},  # decomposed: LATIN A + COMBINING RING ABOVE
        ),
        vec(
            "canon_non_bmp_key_ordering",
            "Object keys MUST be ordered by UTF-16 code unit (§4.3.1, RFC 8785 "
            "§3.2.3), NOT by Unicode code point. The key '\\uE000' (BMP private-use) "
            "vs '\\U0001F511' (🔑, non-BMP) is the discriminating case: by code "
            "point \\uE000 (57344) < 🔑 (128273) so \\uE000 sorts first; by UTF-16 "
            "the 🔑 surrogate lead unit 0xD83D (55357) < 0xE000 so 🔑 sorts first. "
            "A code-point sort (naive Python/Go/Rust) and a UTF-16 sort (JS/.NET) "
            "disagree here — this vector forces all implementations onto UTF-16.",
            {"": 1, "\U0001f511": 2, "a": 3},
        ),
        vec(
            "canon_boundary_integer",
            "Safe-integer boundary 2^53-1 = 9007199254740991 (§4.3.6). This value "
            "round-trips byte-identically everywhere; 2^53 (9007199254740992) is "
            "out of the signed-material domain and MUST be rejected at sign/verify.",
            {"amount": 9007199254740991, "currency": "USD"},
        ),
        vec(
            "canon_control_char_escaping",
            "C0 control characters in string values MUST use the two-char short "
            "escapes \\b \\f \\n \\r \\t where defined, and \\u00XX (lowercase hex) "
            "for every other code point < U+0020 (§4.3.4). '/' is NOT escaped; '\"' "
            "and '\\\\' are. '<' '>' '&' are passed through literally (NOT HTML-"
            "escaped). The five reference encoders are hand-aligned on this; this "
            "vector pins it so a port that emits \\u0008 for backspace, uppercase "
            "hex, or HTML-escapes diverges loudly instead of silently.",
            {"ctl": 'a\bb\tc\nd\re\ffg\x01h/i"j\\k', "lt": "<x>&y"},
        ),
    ]


def _invalid_canonicalization_vectors() -> list[dict]:
    """Inputs that are INVALID signed/hashed material and MUST be rejected, not
    serialised (§4.3.5 floats, §4.3.6 integer domain). Makes the normative
    rejection rules machine-checkable instead of prose-only.

    Self-checked at generation time: each input is asserted to actually raise
    in `_canonical_json`, so the published `must_reject: true` is never a claim
    the reference implementation fails to honour.
    """
    from raucle.provenance import _canonical_json

    cases = [
        (
            "invalid_integer_above_safe_range",
            "2^53 = 9007199254740992 is one past the safe-integer boundary (§4.3.6); "
            "MUST be rejected at sign and verify in every implementation.",
            {"amount": 9007199254740992},
        ),
        (
            "invalid_integer_below_safe_range",
            "-(2^53) = -9007199254740992 is one past the negative boundary (§4.3.6); "
            "MUST be rejected.",
            {"amount": -9007199254740992},
        ),
        (
            "invalid_float",
            "Non-integer numbers (floats) MUST be rejected, not serialised (§4.3.5): "
            "cross-implementation float canonicalisation is out of scope for v1.",
            {"amount": 1.5},
        ),
        (
            "invalid_lone_surrogate",
            "An unpaired UTF-16 surrogate (here a lone HIGH surrogate U+D800 in a "
            "string value) MUST be rejected at sign/verify (§4.3.4). It cannot be "
            "encoded to UTF-8 and the ports otherwise disagree: Python and Rust "
            "reject, Go and .NET substitute U+FFFD, and a JS JSON.stringify emits a "
            "\\udXXX escape — a silent cross-implementation byte divergence. "
            "Rejection is the only portable contract.",
            {"corpus": "\ud800"},
        ),
        (
            "invalid_lone_surrogate_low",
            "A lone LOW surrogate U+DC00 (not preceded by a high) in a string value "
            "MUST be rejected (§4.3.4), same contract as a lone high surrogate. "
            "Distinct code path from the high-surrogate case in every port.",
            {"corpus": "\udc00"},
        ),
        (
            "invalid_lone_surrogate_key",
            "A lone surrogate U+D800 in an OBJECT KEY (not a value) MUST be rejected "
            "(§4.3.4): the rule applies to keys and values alike. Exercises the "
            "key-validation path, which is separate from value validation in the "
            "Python/TypeScript ports.",
            {"\ud800": 1},
        ),
    ]
    out = []
    for name, desc, obj in cases:
        try:
            _canonical_json(obj)
        except Exception as e:  # expected — this is the contract
            out.append(
                {
                    "name": name,
                    "description": desc,
                    "input_object": obj,
                    "must_reject": True,
                    "reference_error": type(e).__name__,
                }
            )
        else:
            raise AssertionError(
                f"{name}: _canonical_json accepted input that the spec says MUST be rejected"
            )
    return out


def _invalid_receipt_vectors() -> list[dict]:
    """Receipts a conformant verifier MUST reject (SPEC §6 byte-equality + R10).

    Each carries a VALID Ed25519 signature over NON-canonical bytes — modelling a
    buggy/malicious emitter that signed non-canonical material. So rejection is
    the §6 canonical / R10 duplicate-key check firing, NOT a signature failure:
    tampering a valid receipt would only test signature rejection. The header is
    kept canonical so the failure isolates to the payload-side verify path.

    Self-checked at generation: the canonical receipt MUST pass strict parsing,
    and every invalid one MUST be rejected by ``from_jws(strict=True)``.
    """
    import json as _json

    from raucle.provenance import (
        _EXPECTED_ALG,
        _EXPECTED_TYP,
        Operation,
        ProvenanceReceipt,
        _b64url_encode,
        _canonical_json,
        hash_text,
    )

    identity = _build_identity()
    # A structurally-valid payload, so a rejection isolates to the canonical /
    # duplicate-key check rather than a missing-field error.
    base = ProvenanceReceipt(
        agent_id=identity.agent_id,
        agent_key_id=identity.key_id,
        operation=Operation.USER_INPUT,
        input_hash=hash_text("Hello, world."),
        taint=["external_user"],
        issued_at=1_700_000_001,
    )
    payload = base.payload()
    canon = _canonical_json(payload)
    header_b64 = _b64url_encode(
        _canonical_json(
            {
                "alg": _EXPECTED_ALG,
                "typ": _EXPECTED_TYP,
                "kid": identity.key_id,
                "crit": ["raucle/v1"],
                "raucle/v1": "provenance",
            }
        )
    )

    def make(payload_bytes: bytes) -> str:
        payload_b64 = _b64url_encode(payload_bytes)
        signing_input = (header_b64 + "." + payload_b64).encode("ascii")
        sig = identity.sign(signing_input)
        return signing_input.decode("ascii") + "." + _b64url_encode(sig)

    # Sanity: the canonical receipt MUST pass strict parsing, else the non-canon
    # vectors below would reject for the wrong reason.
    ProvenanceReceipt.from_jws(make(canon), strict=True)

    reversed_order = _json.dumps(
        {k: payload[k] for k in reversed(list(payload))},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    with_whitespace = _json.dumps(
        payload, separators=(", ", ": "), ensure_ascii=False, sort_keys=True
    ).encode("utf-8")

    # (name, description, payload_bytes, expected_error_substr). The substring is
    # the reason verify MUST reject; the test asserts the rejection message
    # contains it, so a future vector cannot pass for the WRONG reason.
    cases = [
        (
            "invalid_receipt_duplicate_key",
            "Payload has a duplicate object key (R10). A signed JWS whose payload "
            "JSON repeats a key MUST be rejected on verify — duplicate keys are a "
            "parser-differential / signature-confusion vector.",
            canon[:-1] + b',"operation":"user_input"}',
            "duplicate key",
        ),
        (
            "invalid_receipt_noncanonical_key_order",
            "Payload keys are not in canonical (UTF-16 code-unit) order (§6). The "
            "signature is valid over these bytes, but re-encoding canonically does "
            "not reproduce them, so verify MUST reject.",
            reversed_order,
            "not canonical JSON",
        ),
        (
            "invalid_receipt_insignificant_whitespace",
            "Payload has insignificant whitespace after separators (§6). Valid "
            "signature, non-canonical bytes — verify MUST reject.",
            with_whitespace,
            "not canonical JSON",
        ),
        (
            "invalid_receipt_lone_surrogate",
            "Payload string contains an unpaired UTF-16 surrogate (§4.3.4). Re-"
            "encoding rejects it, so verify MUST reject even with a valid signature.",
            canon[:-1] + b',"x":"\\ud800"}',
            "lone surrogate",
        ),
    ]

    out = []
    for name, desc, payload_bytes, expected_substr in cases:
        jws = make(payload_bytes)
        try:
            ProvenanceReceipt.from_jws(jws, strict=True)
        except Exception as e:  # expected — the verifier MUST reject
            if expected_substr not in str(e):
                raise AssertionError(
                    f"{name}: rejected with {e!r}, expected message containing "
                    f"{expected_substr!r} — the vector may be failing for the wrong reason"
                ) from e
            out.append(
                {
                    "name": name,
                    "description": desc,
                    "jws": jws,
                    "must_reject": True,
                    "reference_error": type(e).__name__,
                    "expected_error_substr": expected_substr,
                }
            )
        else:
            raise AssertionError(
                f"{name}: from_jws(strict=True) ACCEPTED a receipt the spec says MUST be rejected"
            )
    return out


def _identity_resolution_policy_vectors() -> list[dict]:
    """Synthetic identity-resolution scenarios for provenance assurance.

    These vectors model identity-assurance policy independently from
    cryptographic receipt validity. The source-control author format used here
    is synthetic and specific to these test vectors; it is not a Raucle
    provenance specification requirement.
    """
    return [
        {
            "name": "principal_resolution_authoritative",
            "description": (
                "Authenticated human principal is resolved from the authoritative "
                "source-control platform API. The asserted artifact author and "
                "authenticated pusher remain bound to the same stable platform "
                "principal."
            ),
            "expected_identity_result": "PASS",
            "human_principal_id": "99887766",
            "human_principal_login": "alex.j.smith",
            "identity_issuer": "SOURCE_CONTROL_PLATFORM",
            "identity_resolution_method": "platform_api",
            "asserted_artifact_author": ("99887766+alex.j.smith@platform.noreply.example"),
            "pusher_principal_id": "99887766",
            "ambient_identifier": "asmith",
            "ambient_namespace": "os_username",
        },
        {
            "name": "principal_resolution_ambient_namespace_collision",
            "description": (
                "AI agent skips authoritative identity resolution and derives the "
                "artifact author from an operating-system username. The OS "
                "identifier exactly matches an unrelated valid source-control "
                "platform login, demonstrating that string equality across identity "
                "namespaces does not establish principal equivalence."
            ),
            "expected_identity_result": "FAIL",
            "human_principal_id": "99887766",
            "human_principal_login": "alex.j.smith",
            "identity_issuer": "SOURCE_CONTROL_PLATFORM",
            "identity_resolution_method": "ambient_os_username",
            "asserted_artifact_author": "asmith@platform.noreply.example",
            "pusher_principal_id": "99887766",
            "ambient_identifier": "asmith",
            "ambient_namespace": "os_username",
        },
        {
            "name": "principal_resolution_authoritative_source_unavailable",
            "description": (
                "Authoritative identity resolution is unavailable. The secure "
                "behavior is to fail closed rather than infer a human principal "
                "from ambient context."
            ),
            "expected_identity_result": "FAIL",
            "human_principal_id": "",
            "human_principal_login": "",
            "identity_issuer": "SOURCE_CONTROL_PLATFORM",
            "identity_resolution_method": "unavailable",
            "asserted_artifact_author": "",
            "pusher_principal_id": "99887766",
            "ambient_identifier": "asmith",
            "ambient_namespace": "os_username",
        },
    ]


def main() -> int:
    vectors = _build_vectors()
    vectors["canonicalization_vectors"] = _canonicalization_vectors()
    vectors["identity_resolution_policy_vectors"] = _identity_resolution_policy_vectors()
    vectors["invalid_canonicalization_vectors"] = _invalid_canonicalization_vectors()
    vectors["invalid_receipt_vectors"] = _invalid_receipt_vectors()
    print(json.dumps(vectors, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
