"""Raucle Gateway - enterprise AI agent governance gateway.

A Docker-deployable gateway that sits between AI agents and their tools.
Enforces capability gates, produces signed receipts, and provides an
admin panel for policy configuration, statistics, and log forwarding.

Architecture:

    AI Agent -> [Raucle Gateway] -> Tool (API, MCP, function call)
                   |
                   +-> Admin Panel (FastAPI web UI)
                   +-> Receipt Store (JSONL / S3 / Kafka)
                   +-> SIEM Forwarder (Splunk HEC / Elastic / Azure Sentinel)
                   +-> Policy Engine (YAML DSL)
                   +-> KMS Signer (AWS / Azure / Vault)

Admin panel features:
  - Policy management: create, edit, validate, deploy policies (YAML DSL)
  - Dashboard: gate decisions (allow/deny counts), latency, top tools
  - Receipt viewer: browse and verify provenance receipts
  - Log forwarding: configure SIEM destinations (Splunk, Elastic, Sentinel)
  - User management: admin, operator, auditor roles (API key auth)
  - Configuration: KMS signer, registry, compliance framework settings
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class GatewayConfig:
    """Gateway configuration loaded from environment or config file."""

    # Core
    host: str = "0.0.0.0"
    port: int = 8080
    admin_port: int = 8081
    admin_api_key: str = ""

    # Signer
    signer_backend: str = "local"  # local, aws, azure, vault
    kms_key_id: str = ""
    kms_region: str = "eu-west-1"

    # Policy
    policy_file: str = "/etc/raucle/policies.yaml"

    # Receipts
    receipt_store: str = "/data/receipts.jsonl"
    audit_chain: str = "/data/audit.jsonl"

    # SIEM
    siem_enabled: bool = False
    siem_backend: str = ""  # splunk, elastic, sentinel, kafka
    siem_url: str = ""
    siem_token: str = ""

    # Compliance
    compliance_framework: str = "eu-ai-act"  # eu-ai-act, iso-42001, soc2

    # Registry
    registry_path: str = "/data/registry.jsonl"

    @classmethod
    def from_env(cls) -> GatewayConfig:
        """Load configuration from environment variables."""
        return cls(
            host=os.environ.get("RAUCLE_GATEWAY_HOST", "0.0.0.0"),
            port=int(os.environ.get("RAUCLE_GATEWAY_PORT", "8080")),
            admin_port=int(os.environ.get("RAUCLE_ADMIN_PORT", "8081")),
            admin_api_key=os.environ.get("RAUCLE_ADMIN_KEY", ""),
            signer_backend=os.environ.get("RAUCLE_SIGNER", "local"),
            kms_key_id=os.environ.get("RAUCLE_KMS_KEY_ID", ""),
            kms_region=os.environ.get("AWS_REGION", "eu-west-1"),
            policy_file=os.environ.get("RAUCLE_POLICY_FILE", "/etc/raucle/policies.yaml"),
            receipt_store=os.environ.get("RAUCLE_RECEIPT_STORE", "/data/receipts.jsonl"),
            audit_chain=os.environ.get("RAUCLE_AUDIT_CHAIN", "/data/audit.jsonl"),
            siem_enabled=os.environ.get("RAUCLE_Siem_ENABLED", "").lower() in ("1", "true", "yes"),
            siem_backend=os.environ.get("RAUCLE_Siem_BACKEND", ""),
            siem_url=os.environ.get("RAUCLE_Siem_URL", ""),
            siem_token=os.environ.get("RAUCLE_Siem_TOKEN", ""),
            compliance_framework=os.environ.get("RAUCLE_COMPLIANCE_FRAMEWORK", "eu-ai-act"),
            registry_path=os.environ.get("RAUCLE_REGISTRY_PATH", "/data/registry.jsonl"),
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> GatewayConfig:
        """Load from a YAML config file."""
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


@dataclass
class GatewayStats:
    """Live gateway statistics for the admin dashboard."""

    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_requests: int = 0
    allowed: int = 0
    denied: int = 0
    escalated: int = 0
    by_tool: dict[str, dict[str, int]] = field(default_factory=dict)
    latency_us_total: int = 0
    latency_us_count: int = 0

    def record(self, tool: str, decision: str, latency_us: int) -> None:
        self.total_requests += 1
        if decision == "allow":
            self.allowed += 1
            self.by_tool.setdefault(tool, {})
            self.by_tool[tool]["allow"] = self.by_tool[tool].get("allow", 0) + 1
        elif decision == "deny":
            self.denied += 1
            self.by_tool.setdefault(tool, {})
            self.by_tool[tool]["deny"] = self.by_tool[tool].get("deny", 0) + 1
        else:
            self.escalated += 1
            self.by_tool.setdefault(tool, {})
            self.by_tool[tool][decision] = self.by_tool[tool].get(decision, 0) + 1
        self.latency_us_total += latency_us
        self.latency_us_count += 1

    def summary(self) -> dict[str, Any]:
        avg_latency = (
            self.latency_us_total / self.latency_us_count if self.latency_us_count > 0 else 0
        )
        return {
            "uptime_since": self.start_time,
            "total_requests": self.total_requests,
            "allowed": self.allowed,
            "denied": self.denied,
            "escalated": self.escalated,
            "avg_latency_us": round(avg_latency, 1),
            "tools": dict(self.by_tool),
        }


# ---------------------------------------------------------------------------
# SIEM Forwarder
# ---------------------------------------------------------------------------


class SIEMForwarder:
    """Forward gate decisions to a SIEM system.

    Supports Splunk HEC, Elasticsearch, and Azure Sentinel (Log Analytics).
    Falls back to local logging if SIEM is unreachable.
    """

    def __init__(self, config: GatewayConfig) -> None:
        self.enabled = config.siem_enabled
        self.backend = config.siem_backend
        self.url = config.siem_url
        self.token = config.siem_token
        self._buffer: list[dict[str, Any]] = []

    def forward(self, event: dict[str, Any]) -> None:
        """Send a gate decision event to the configured SIEM."""
        if not self.enabled:
            self._buffer.append(event)
            if len(self._buffer) > 100:
                self._buffer.pop(0)
            return

        try:
            if self.backend == "splunk":
                self._forward_splunk(event)
            elif self.backend == "elastic":
                self._forward_elastic(event)
            elif self.backend == "sentinel":
                self._forward_sentinel(event)
        except Exception as exc:
            logger.warning("SIEM forward failed: %s", exc)
            self._buffer.append(event)

    def _forward_splunk(self, event: dict[str, Any]) -> None:
        import requests

        headers = {"Authorization": f"Splunk {self.token}"}
        payload = {"event": event, "sourcetype": "raucle:gate"}
        requests.post(self.url, json=payload, headers=headers, timeout=5)

    def _forward_elastic(self, event: dict[str, Any]) -> None:
        import requests

        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"ApiKey {self.token}"
        requests.post(self.url, json=event, headers=headers, timeout=5)

    def _forward_sentinel(self, event: dict[str, Any]) -> None:
        """Azure Sentinel via Log Analytics Data Collector API."""
        import base64
        import hashlib
        import hmac

        import requests

        workspace_id = os.environ.get("AZURE_LOG_ANALYTICS_WORKSPACE_ID", "")
        shared_key = os.environ.get("AZURE_LOG_ANALYTICS_SHARED_KEY", "")
        if not workspace_id or not shared_key:
            return

        body = json.dumps(event)
        resource = "/api/logs"
        rfc1123date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_length = len(body)
        signed_content = f"POST\n{content_length}\napplication/json\n{rfc1123date}{resource}"
        decoded_key = base64.b64decode(shared_key)
        signature = hmac.new(decoded_key, signed_content.encode("utf-8"), hashlib.sha256).digest()
        encoded_sig = base64.b64encode(signature).decode("ascii")
        auth_header = f"SharedKey {workspace_id}:{encoded_sig}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": auth_header,
            "x-ms-date": rfc1123date,
        }
        url = f"https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
        requests.post(url, data=body, headers=headers, timeout=5)

    def buffered_events(self) -> list[dict[str, Any]]:
        """Return events that couldn't be forwarded (for admin panel display)."""
        return list(self._buffer)


# ---------------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------------


@dataclass
class GatewayUser:
    """An admin panel user."""

    api_key: str
    role: str  # admin, operator, auditor
    name: str = ""


class UserManager:
    """Simple API-key-based user management for the admin panel.

    Roles:
    - admin: full access (policies, users, config, stats, receipts)
    - operator: policies, stats, receipts (no user management)
    - auditor: stats, receipts (read-only)
    """

    def __init__(self) -> None:
        self._users: dict[str, GatewayUser] = {}

    def add_user(self, api_key: str, role: str, name: str = "") -> GatewayUser:
        user = GatewayUser(api_key=api_key, role=role, name=name)
        self._users[api_key] = user
        return user

    def get_user(self, api_key: str) -> GatewayUser | None:
        return self._users.get(api_key)

    def list_users(self) -> list[GatewayUser]:
        return list(self._users.values())

    def remove_user(self, api_key: str) -> bool:
        if api_key in self._users:
            del self._users[api_key]
            return True
        return False

    def can_access(self, api_key: str, resource: str) -> bool:
        """Check if a user can access a resource."""
        user = self._users.get(api_key)
        if user is None:
            return False
        if user.role == "admin":
            return True
        if user.role == "operator":
            return resource in ("policies", "stats", "receipts", "config")
        if user.role == "auditor":
            return resource in ("stats", "receipts")
        return False


# ---------------------------------------------------------------------------
# Gateway core
# ---------------------------------------------------------------------------


class RaucleGateway:
    """The gateway core: policy engine + gate + receipt store + stats.

    This is the stateful core that the FastAPI admin panel and the
    gateway proxy endpoints share.
    """

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self.stats = GatewayStats()
        self.siem = SIEMForwarder(config)
        self.users = UserManager()
        self._tokens: dict[str, Any] = {}  # tool_name -> Capability
        self._policy_rules: dict[str, Any] = {}  # tool_name -> PolicyRule
        self._signer = None
        self._issuer: Any = None
        self._gate: Any = None
        self._receipt_writer = None

        # Bootstrap from config
        self._init_signer()
        self._load_policies()

    def _init_signer(self) -> None:
        """Initialise the signer (local or KMS)."""
        from raucle.kms import create_signer

        if self.config.signer_backend == "local":
            from raucle.audit import Ed25519Signer

            self._signer = Ed25519Signer.generate()
        else:
            self._signer = create_signer(
                backend=self.config.signer_backend,
                key_id=self.config.kms_key_id,
                region=self.config.kms_region,
            )

        # Create issuer from signer
        from raucle.capability import CapabilityIssuer

        if self.config.signer_backend == "local":
            # Local signer has a private key - use generate
            self._issuer = CapabilityIssuer.generate(issuer="raucle-gateway")
        else:
            self._issuer = CapabilityIssuer.from_signer("raucle-gateway", self._signer)

        # Create gate
        from raucle.capability import CapabilityGate

        self._gate = CapabilityGate(
            trusted_issuers={self._issuer.key_id: self._issuer.public_key_pem}
        )

    def _load_policies(self) -> None:
        """Load policies from the configured YAML file."""
        path = Path(self.config.policy_file)
        if not path.exists():
            logger.info("No policy file at %s, running with no policies", path)
            return

        try:
            from raucle.policy import PolicyFile, mint_from_policy

            policy = PolicyFile.load(path)
            self._tokens = mint_from_policy(policy, self._issuer)
            self._policy_rules = {r.tool: r for r in policy.policies}
            logger.info("Loaded %d policy rules from %s", len(self._policy_rules), path)
        except Exception as exc:
            logger.error("Failed to load policies: %s", exc)

    def check_tool_call(
        self,
        tool: str,
        args: dict[str, Any],
        agent_id: str = "",
    ) -> dict[str, Any]:
        """Gate a tool call. Returns decision dict.

        Returns:
            {
                "decision": "allow" | "deny" | "escalate",
                "reason": str,
                "tool": str,
                "args_hash": str,
                "receipt_id": str | None,
                "latency_us": int,
            }
        """
        start = time.perf_counter()

        result: dict[str, Any] = {
            "tool": tool,
            "decision": "deny",
            "reason": "unknown tool",
            "args_hash": "",
            "receipt_id": None,
        }

        if tool not in self._tokens:
            result["reason"] = f"no policy configured for tool '{tool}'"
            self.stats.record(tool, "deny", int((time.perf_counter() - start) * 1e6))
            self.siem.forward(
                {
                    "event": "gate_decision",
                    "tool": tool,
                    "decision": "deny",
                    "reason": result["reason"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            result["latency_us"] = int((time.perf_counter() - start) * 1e6)
            return result

        token = self._tokens[tool]
        actual_agent_id = agent_id or token.agent_id

        # Gate check
        decision = self._gate.check(
            token,
            tool=tool,
            agent_id=actual_agent_id,
            args=args,
        )

        if decision.allowed:
            # Check if approval is needed
            from raucle.policy import check_approval_needed

            rule = self._policy_rules.get(tool)
            if rule and check_approval_needed(rule, args):
                result["decision"] = "escalate"
                result["reason"] = "requires human approval"
            else:
                result["decision"] = "allow"
                result["reason"] = decision.reason
        else:
            result["decision"] = "deny"
            result["reason"] = decision.reason

        # Record stats
        latency_us = int((time.perf_counter() - start) * 1e6)
        self.stats.record(tool, result["decision"], latency_us)

        # Forward to SIEM
        self.siem.forward(
            {
                "event": "gate_decision",
                "tool": tool,
                "decision": result["decision"],
                "reason": result["reason"],
                "args": args,
                "agent_id": actual_agent_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "latency_us": latency_us,
            }
        )

        result["latency_us"] = latency_us
        return result

    def get_stats(self) -> dict[str, Any]:
        return self.stats.summary()

    def reload_policies(self) -> dict[str, Any]:
        """Hot-reload policies from the config file."""
        try:
            self._load_policies()
            return {"status": "ok", "policies": len(self._policy_rules)}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}


__all__ = [
    "GatewayConfig",
    "GatewayStats",
    "SIEMForwarder",
    "GatewayUser",
    "UserManager",
    "RaucleGateway",
]
