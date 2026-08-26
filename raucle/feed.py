r"""Federated signed-IOC feed -- the AI-security equivalent of a CT log.

Every Indicator of Compromise (IOC) is content-addressed and Ed25519-signed
by its publisher. Feeds are Merkle-rooted manifests that consumers fetch,
verify against a pinned issuer pubkey, and merge into the local Scanner.

There is no central authority: each consumer maintains a small
``trusted_issuers`` allowlist. Multiple feeds can be subscribed
simultaneously. A compromised feed cannot mutate prior IOCs silently --
every IOC carries its own signature, verifiable offline.

Usage (publisher)::

    from raucle.feed import IOCSigner, SignedIOC
    signer = IOCSigner.generate(issuer="raucle.io")
    signer.save_private_key("issuer.pem")
    ioc = signer.sign_ioc(
        kind="regex",
        pattern=r"(?i)ignore\s+all\s+previous",
        severity="high",
        categories=["direct_injection"],
        description="Classic instruction-override jailbreak",
    )
    feed = signer.build_feed([ioc], feed_id="raucle/core")
    feed.save("feed.json")

Usage (consumer)::

    from raucle.feed import Feed, FeedStore
    feed = Feed.load("feed.json")
    feed.verify(pubkey_pem=trusted_pem)  # raises if signature/root invalid
    store = FeedStore.open("~/.raucle/feeds")
    store.merge(feed)
    rules = store.as_pattern_rules()  # feed into Scanner(extra_patterns=...)

Design
------
- IOC kinds: ``regex``, ``substring``, ``unicode_signature``. Future:
  ``embedding`` (cosine), ``ast`` (tool-call shape).
- Canonical JSON for hashing; Ed25519 over the canonical bytes.
- Feed manifest carries a Merkle root over sorted IOC content hashes,
  signed once. Adding/removing IOCs requires re-signing.
- Revocation: publish a feed entry with ``revokes=[<content_hash>]``.
  Consumers honour revocations from the same issuer only.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from raucle._paths import validate_path

from ._canon import utf16_key as _u16  # UTF-16 ordering for signed value lists

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonicalisation primitives (mirrors provenance.py for consistency)
# ---------------------------------------------------------------------------


_SHA256_PREFIX = "sha256:"  # named once (Sonar S1192)


def _canonical_json(obj: Any) -> bytes:
    # UTF-16 code-unit key ordering (shared _canon helper) for cross-language
    # byte-identity. allow_nan=False: NaN/Infinity are not valid JSON and break
    # cross-language signature verification (round-3 #13).
    from ._canon import reorder_keys_utf16

    return json.dumps(
        reorder_keys_utf16(obj),
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _now() -> int:
    return int(dt.datetime.now(dt.timezone.utc).timestamp())


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


IOC_KINDS = frozenset({"regex", "substring", "unicode_signature"})
SEVERITIES = frozenset({"low", "medium", "high", "critical"})


@dataclass
class SignedIOC:
    """A single signed Indicator of Compromise.

    The ``content_hash`` is the canonical identifier and binds every
    field below the signature. The ``signature`` covers the canonical
    JSON of :meth:`body`.
    """

    kind: str
    pattern: str
    severity: str
    categories: list[str]
    description: str
    issuer: str
    key_id: str
    issued_at: int
    revokes: list[str] = field(default_factory=list)
    expires_at: int | None = None
    content_hash: str = ""
    signature: str = ""

    def body(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "pattern": self.pattern,
            "severity": self.severity,
            "categories": sorted(self.categories, key=_u16),
            "description": self.description,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "issued_at": self.issued_at,
            "revokes": sorted(self.revokes, key=_u16),
            "expires_at": self.expires_at,
        }

    def compute_content_hash(self) -> str:
        return _SHA256_PREFIX + _sha256_hex(_canonical_json(self.body()))

    def to_dict(self) -> dict[str, Any]:
        d = self.body()
        d["content_hash"] = self.content_hash
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SignedIOC:
        return cls(
            kind=d["kind"],
            pattern=d["pattern"],
            severity=d["severity"],
            categories=list(d.get("categories", [])),
            description=d.get("description", ""),
            issuer=d["issuer"],
            key_id=d["key_id"],
            issued_at=int(d["issued_at"]),
            revokes=list(d.get("revokes", [])),
            expires_at=d.get("expires_at"),
            content_hash=d.get("content_hash", ""),
            signature=d.get("signature", ""),
        )

    def validate_shape(self) -> None:
        if self.kind not in IOC_KINDS:
            raise ValueError(f"unknown ioc kind: {self.kind!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity!r}")
        if not self.pattern:
            raise ValueError("pattern must not be empty")
        if not self.issuer:
            raise ValueError("issuer must not be empty")


@dataclass
class Feed:
    """A signed bundle of IOCs from a single issuer.

    The feed manifest carries a Merkle root over the sorted content
    hashes of its IOCs and a single signature over the manifest body.
    Every IOC inside is *also* individually signed -- the feed
    signature is a convenience for batch verification, not a
    substitute.
    """

    feed_id: str
    issuer: str
    key_id: str
    public_key_pem: str
    issued_at: int
    iocs: list[SignedIOC] = field(default_factory=list)
    merkle_root: str = ""
    signature: str = ""
    version: str = "raucle-feed/v1"

    def compute_merkle_root(self) -> str:
        hashes = sorted((i.content_hash for i in self.iocs), key=_u16)
        if not hashes:
            return _SHA256_PREFIX + _sha256_hex(b"")
        return _SHA256_PREFIX + _sha256_hex(_canonical_json(hashes))

    def manifest_body(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "feed_id": self.feed_id,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "issued_at": self.issued_at,
            "merkle_root": self.merkle_root,
            "ioc_count": len(self.iocs),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.manifest_body(),
            "signature": self.signature,
            "iocs": [i.to_dict() for i in self.iocs],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Feed:
        return cls(
            feed_id=d["feed_id"],
            issuer=d["issuer"],
            key_id=d["key_id"],
            public_key_pem=d["public_key_pem"],
            issued_at=int(d["issued_at"]),
            iocs=[SignedIOC.from_dict(i) for i in d.get("iocs", [])],
            merkle_root=d.get("merkle_root", ""),
            signature=d.get("signature", ""),
            version=d.get("version", "raucle-feed/v1"),
        )

    def save(self, path: str | Path) -> None:
        validate_path(path, must_exist=False).write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        )

    @classmethod
    def load(cls, path: str | Path) -> Feed:
        return cls.from_dict(json.loads(validate_path(path).read_text()))

    def verify(self, *, pubkey_pem: str | None = None) -> None:
        """Verify Merkle root, manifest signature, and every IOC signature.

        Raises ``ValueError`` on any mismatch. If ``pubkey_pem`` is
        provided, it must match the feed's embedded key; this is the
        consumer's pinning check.
        """
        if pubkey_pem is not None and pubkey_pem.strip() != self.public_key_pem.strip():
            raise ValueError("pinned pubkey does not match feed's embedded public key")

        expected_root = self.compute_merkle_root()
        if expected_root != self.merkle_root:
            raise ValueError(
                f"merkle root mismatch: feed declares {self.merkle_root}, computed {expected_root}"
            )

        pub = _load_pubkey(self.public_key_pem)
        _ed25519_verify(pub, _canonical_json(self.manifest_body()), _b64d(self.signature))

        for ioc in self.iocs:
            expected_h = ioc.compute_content_hash()
            if expected_h != ioc.content_hash:
                raise ValueError(
                    f"ioc content_hash mismatch: declared {ioc.content_hash}, computed {expected_h}"
                )
            _ed25519_verify(pub, _canonical_json(ioc.body()), _b64d(ioc.signature))


# ---------------------------------------------------------------------------
# Crypto helpers (lazy-import cryptography)
# ---------------------------------------------------------------------------


def _require_crypto() -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "raucle.feed requires the [compliance] extra: pip install 'raucle[compliance]'"
        ) from exc
    return serialization, ed25519


def _load_pubkey(pem: str) -> Any:
    serialization, _ = _require_crypto()
    return serialization.load_pem_public_key(pem.encode("ascii"))


def _ed25519_verify(pub: Any, data: bytes, sig: bytes) -> None:
    try:
        pub.verify(sig, data)
    except Exception as exc:
        raise ValueError(f"signature verification failed: {exc}") from exc


def _write_private_bytes(path: Path, data: bytes) -> None:
    """Write secret key material with owner-only (0600) permissions.

    The file is created with a restrictive mode from the outset (via
    ``os.open`` with mode ``0o600``) so the secret is never momentarily
    world-readable, and the mode is re-asserted afterwards in case the
    file already existed.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    # Re-assert in case the file pre-existed with looser permissions.
    os.chmod(str(path), 0o600)


# ---------------------------------------------------------------------------
# Publisher
# ---------------------------------------------------------------------------


class IOCSigner:
    """Holds an Ed25519 private key and signs IOCs / feeds."""

    def __init__(self, issuer: str, private_key: Any) -> None:
        if not issuer:
            raise ValueError("issuer must not be empty")
        self.issuer = issuer
        self._priv = private_key
        serialization, _ = _require_crypto()
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_pem = pub_pem.decode("ascii")
        self.key_id = _sha256_hex(pub_pem)[:16]

    @classmethod
    def generate(cls, issuer: str) -> IOCSigner:
        _, ed25519 = _require_crypto()
        return cls(issuer=issuer, private_key=ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def load_private_key(cls, issuer: str, path: str | Path) -> IOCSigner:
        serialization, _ = _require_crypto()
        priv = serialization.load_pem_private_key(validate_path(path).read_bytes(), password=None)
        return cls(issuer=issuer, private_key=priv)

    def save_private_key(self, path: str | Path) -> None:
        serialization, _ = _require_crypto()
        pem = self._priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        _write_private_bytes(Path(path), pem)

    def sign_ioc(
        self,
        *,
        kind: str,
        pattern: str,
        severity: str,
        categories: list[str],
        description: str = "",
        revokes: list[str] | None = None,
        expires_at: int | None = None,
    ) -> SignedIOC:
        ioc = SignedIOC(
            kind=kind,
            pattern=pattern,
            severity=severity,
            categories=list(categories),
            description=description,
            issuer=self.issuer,
            key_id=self.key_id,
            issued_at=_now(),
            revokes=list(revokes or []),
            expires_at=expires_at,
        )
        ioc.validate_shape()
        ioc.content_hash = ioc.compute_content_hash()
        ioc.signature = _b64(self._priv.sign(_canonical_json(ioc.body())))
        return ioc

    def build_feed(self, iocs: list[SignedIOC], *, feed_id: str) -> Feed:
        for ioc in iocs:
            if ioc.issuer != self.issuer or ioc.key_id != self.key_id:
                raise ValueError(f"ioc {ioc.content_hash} was signed by a different issuer/key")
        feed = Feed(
            feed_id=feed_id,
            issuer=self.issuer,
            key_id=self.key_id,
            public_key_pem=self.public_key_pem,
            issued_at=_now(),
            iocs=list(iocs),
        )
        feed.merkle_root = feed.compute_merkle_root()
        feed.signature = _b64(self._priv.sign(_canonical_json(feed.manifest_body())))
        return feed


# ---------------------------------------------------------------------------
# Consumer: persistent store + scanner integration
# ---------------------------------------------------------------------------


class FeedStore:
    """A directory-backed store of verified feeds.

    Each subscribed feed is saved as ``<feed_id>.json``. Calling
    :meth:`merge` re-verifies and atomically replaces the on-disk
    copy. Revocations from the same issuer are honoured when
    rendering pattern rules.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    @classmethod
    def open(cls, path: str | Path) -> FeedStore:
        return cls(Path(path).expanduser())

    def _feed_path(self, feed_id: str) -> Path:
        safe = feed_id.replace("/", "__").replace("..", "_")
        return self.root / f"{safe}.json"

    def merge(self, feed: Feed, *, pubkey_pem: str | None = None) -> None:
        feed.verify(pubkey_pem=pubkey_pem)
        path = self._feed_path(feed.feed_id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(feed.to_dict(), indent=2, ensure_ascii=False))
        tmp.replace(path)

    def list_feeds(self) -> list[Feed]:
        feeds: list[Feed] = []
        for p in sorted(self.root.glob("*.json")):
            try:
                feeds.append(Feed.load(p))
            except Exception as exc:
                logger.warning("skipping unreadable feed %s: %s", p, exc)
        return feeds

    def all_iocs(self) -> list[SignedIOC]:
        """Return all non-revoked, non-expired IOCs across all subscribed feeds."""
        now = _now()
        # Collect revocations per-issuer first; an issuer can only revoke its own IOCs.
        revocations: dict[str, set[str]] = {}
        all_iocs: list[SignedIOC] = []
        for feed in self.list_feeds():
            for ioc in feed.iocs:
                revocations.setdefault(ioc.issuer, set()).update(ioc.revokes)
                all_iocs.append(ioc)
        result: list[SignedIOC] = []
        for ioc in all_iocs:
            if ioc.content_hash in revocations.get(ioc.issuer, set()):
                continue
            if ioc.expires_at is not None and now >= ioc.expires_at:
                continue
            result.append(ioc)
        return result

    def as_pattern_rules(self) -> list[dict[str, Any]]:
        """Render the live IOC set as Scanner-compatible pattern rules."""
        rules: list[dict[str, Any]] = []
        for ioc in self.all_iocs():
            if ioc.kind == "regex":
                pattern = ioc.pattern
            elif ioc.kind == "substring":
                import re

                pattern = re.escape(ioc.pattern)
            elif ioc.kind == "unicode_signature":
                # pattern is a hex codepoint list, e.g. "200B,202E"; match any.
                cps = [c.strip() for c in ioc.pattern.split(",") if c.strip()]
                pattern = "|".join(f"\\u{c.zfill(4)}" for c in cps)
            else:
                continue
            cats = list(ioc.categories) or ["feed_ioc"]
            rules.append(
                {
                    "id": f"feed:{ioc.issuer}:{ioc.content_hash[7:23]}",
                    "patterns": [pattern],
                    "category": cats[0],
                    "severity": ioc.severity,
                    "score": _severity_to_score(ioc.severity),
                    "technique": ioc.description[:120] or "signed_ioc",
                    "source": f"feed:{ioc.issuer}",
                }
            )
        return rules


def _severity_to_score(severity: str) -> float:
    return {"low": 0.4, "medium": 0.65, "high": 0.85, "critical": 0.95}.get(severity, 0.5)


# ---------------------------------------------------------------------------
# Fetcher (stdlib only, optional)
# ---------------------------------------------------------------------------


# Maximum feed body we are willing to read into memory (8 MiB). Feeds are
# small JSON manifests; anything larger is treated as hostile / malformed.
_MAX_FEED_BYTES = 8 * 1024 * 1024

# Cloud-provider link-local metadata endpoint (AWS/GCP/Azure IMDS).
# This IP is intentionally hardcoded: it is a well-known, stable link-local
# address used as a BLOCKLIST entry in _is_blocked_ip() to prevent SSRF
# attacks that target the cloud metadata service. It is never used as a
# connection target.  noqa: S1313 (sonar: hardcoded IP is safe here).
_METADATA_IP = "169.254.169.254"  # noqa: S1313


def _is_blocked_ip(ip: str) -> bool:
    """True if ``ip`` is private, loopback, link-local, or otherwise non-routable.

    Also explicitly blocks the cloud metadata IP (which is link-local and so
    would be caught anyway, but we name it for clarity / defence in depth).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # Unparseable address — fail closed.
        return True
    if ip == _METADATA_IP:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _assert_safe_url(url: str) -> tuple[str, str]:
    """Validate ``url`` for SSRF safety, returning ``(hostname, pinned_ip)``.

    Enforces:
      * scheme must be exactly ``https`` (rejects file/ftp/http/etc.);
      * the host must resolve only to public, routable IP addresses
        (rejects loopback/private/link-local and the metadata IP).

    Raises ``ValueError`` on any violation.
    """
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ValueError(
            f"refusing to fetch feed: only https:// URLs are allowed, got scheme {parts.scheme!r}"
        )
    host = parts.hostname
    if not host:
        raise ValueError("refusing to fetch feed: URL has no host")

    # Resolve the hostname and verify every resolved address is public. If
    # the host is itself a literal IP, getaddrinfo returns it unchanged.
    try:
        infos = socket.getaddrinfo(host, parts.port or 443, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise ValueError(f"refusing to fetch feed: cannot resolve host {host!r}: {exc}") from exc

    # Preserve resolution order; dedupe without losing the first address. A set
    # is not subscriptable, so `resolved[0]` raised TypeError on every call,
    # leaving the entire SSRF-pinning path as dead code (round-3 #21).
    seen: set[str] = set()
    resolved: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            resolved.append(ip)
    if not resolved:
        raise ValueError(f"refusing to fetch feed: host {host!r} resolved to no addresses")
    for ip in resolved:
        if _is_blocked_ip(ip):
            raise ValueError(
                f"refusing to fetch feed: host {host!r} resolves to "
                f"disallowed (private/loopback/link-local/metadata) address {ip}"
            )
    # Pin the validated address so the connection dials exactly the IP we
    # checked — closes the DNS-rebind / TOCTOU window where a second lookup
    # at connect time could return a blocked address.
    return host, resolved[0]


def fetch_https_pinned(
    url: str, *, timeout: float = 10.0, max_bytes: int = _MAX_FEED_BYTES
) -> bytes:
    """Fetch ``url`` over HTTPS and return the raw body, hardened against SSRF.

    Only ``https://`` URLs whose host resolves to a public, routable IP are
    permitted; the connection is **pinned to the validated IP** (no second DNS
    lookup at connect time, defeating DNS-rebinding); redirects are NOT followed;
    and the body is capped at ``max_bytes``. Shared by feed fetching and the
    trust-registry client so the SSRF guard lives in exactly one place.
    """
    import http.client
    import ssl
    from urllib.parse import urlsplit

    host, pinned_ip = _assert_safe_url(url)
    parts = urlsplit(url)
    port = parts.port or 443
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    ctx = ssl.create_default_context()
    # Pin a TLS 1.2 floor explicitly (defence in depth against downgrade).
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # SSRF protection: DNS resolution is pinned, redirects are refused,
    # and private/loopback/metadata IPs are blocked by _is_blocked_ip.
    class _PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:  # type: ignore[override]
            sock = socket.create_connection((pinned_ip, port), timeout)
            self.sock = ctx.wrap_socket(sock, server_hostname=host)

    conn = _PinnedHTTPSConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "raucle/1", "Host": host})
        resp = conn.getresponse()
        if resp.status in (301, 302, 303, 307, 308):
            raise ValueError(f"refusing to follow redirect (status {resp.status})")
        if resp.status != 200:
            raise ValueError(f"refusing to load: HTTP {resp.status}")
        data = resp.read(max_bytes + 1)
    finally:
        conn.close()
    if len(data) > max_bytes:
        raise ValueError(f"refusing to load: response body exceeds {max_bytes} bytes")
    return data


def fetch_feed(url: str, *, timeout: float = 10.0) -> Feed:
    """Fetch a feed over HTTPS (SSRF-guarded). The caller MUST then verify
    against a pinned pubkey."""
    return Feed.from_dict(json.loads(fetch_https_pinned(url, timeout=timeout)))
