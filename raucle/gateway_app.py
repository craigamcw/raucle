"""Admin panel + gateway API FastAPI application.

This module provides:
  - Gateway API on port 8080: POST /gate (agent tool calls)
  - Admin panel on port 8081: policy management, stats, receipts, config
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from raucle.gateway import (
    GatewayUser,
    RaucleGateway,
    UserManager,
)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class GateRequest(BaseModel):
    """A tool call from an AI agent to be gated."""

    tool: str = Field(..., description="Tool name to call")
    args: dict[str, Any] = Field(default_factory=dict, description="Tool call arguments")
    agent_id: str = Field(default="", description="Agent identity (optional, defaults to policy)")
    source: str = Field(default="", description="Inbound source (agent name, IP, or service ID)")
    destination: str = Field(
        default="", description="Outbound destination (API endpoint, service, or tool target)"
    )


class PolicyUpdateRequest(BaseModel):
    """A policy file update from the admin panel."""

    content: str = Field(..., description="YAML policy content")


class UserCreateRequest(BaseModel):
    """Create a new admin panel user."""

    api_key: str
    role: str = Field(..., description="admin, operator, or auditor")
    name: str = Field(default="")


class SIEMConfigRequest(BaseModel):
    """Update SIEM forwarding configuration."""

    enabled: bool = False
    backend: str = Field(default="", description="splunk, elastic, sentinel")
    url: str = ""
    token: str = ""


# ---------------------------------------------------------------------------
# Gateway API (port 8080)
# ---------------------------------------------------------------------------


def create_gateway_app(gateway: RaucleGateway) -> FastAPI:
    """Create the gateway API app (agent-facing)."""
    app = FastAPI(
        title="Raucle Gateway",
        description="AI agent governance gateway",
        version="0.1.0",
    )
    _limiter = None
    try:
        from slowapi import Limiter
        from slowapi.errors import RateLimitExceeded
        from slowapi.middleware import SlowAPIMiddleware
        from slowapi.util import get_remote_address

        _limiter = Limiter(key_func=get_remote_address, default_limits=["1000/minute"])
        app.state.limiter = _limiter
        app.add_exception_handler(
            RateLimitExceeded,
            lambda req, exc: JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded", "retry_after": "60"},
            ),
        )
        app.add_middleware(SlowAPIMiddleware)
    except ImportError:
        pass  # slowapi not installed, no rate limiting

    @app.post("/gate")
    def gate_tool_call(request: Request, req: GateRequest) -> dict[str, Any]:
        """Gate a tool call. Returns allow/deny/escalate decision."""
        return gateway.check_tool_call(
            req.tool, req.args, req.agent_id, req.source, req.destination
        )

    @app.get("/health")
    def health(authorization: str | None = Header(None)) -> dict[str, str]:
        if gateway.config.health_check_token:
            key = authorization or ""
            if key.startswith("Bearer "):
                key = key[7:]
            import hmac as _hmac

            if not _hmac.compare_digest(key, gateway.config.health_check_token):
                raise HTTPException(status_code=401, detail="Health check unauthorized")
        return {"status": "ok"}

    return app


# ---------------------------------------------------------------------------
# Admin Panel API (port 8081)
# ---------------------------------------------------------------------------


def create_admin_app(gateway: RaucleGateway, users: UserManager) -> FastAPI:
    """Create the admin panel app (operator-facing)."""
    app = FastAPI(
        title="Raucle Gateway Admin",
        description="Enterprise admin panel for policy, stats, and config",
        version="0.1.0",
    )

    def check_auth(authorization: str | None = Header(None)) -> GatewayUser:
        """Extract and validate the API key from the Authorization header."""
        if authorization is None:
            raise HTTPException(status_code=401, detail="Missing Authorization header")
        # Accept "Bearer <key>" or just "<key>"
        key = authorization
        if key.startswith("Bearer "):
            key = key[7:]
        user = users.get_user(key)
        if user is None:
            raise HTTPException(status_code=403, detail="Invalid API key")
        return user

    def check_access(user: GatewayUser, resource: str) -> None:
        if not users.can_access(user.api_key, resource):
            raise HTTPException(
                status_code=403, detail=f"Role '{user.role}' cannot access '{resource}'"
            )

    # --- Health (optional auth via health_key) ---
    @app.get("/health")
    def admin_health(authorization: str | None = Header(None)) -> dict[str, str]:
        if gateway.config.health_check_token:
            key = authorization or ""
            if key.startswith("Bearer "):
                key = key[7:]
            import hmac as _hmac

            if not _hmac.compare_digest(key, gateway.config.health_check_token):
                raise HTTPException(status_code=401, detail="Health check unauthorized")
        return {"status": "ok"}

    # --- Dashboard / Stats ---
    @app.get("/api/stats")
    def get_stats(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "stats")
        return gateway.get_stats()

    # --- Connections (live flow log) ---
    @app.get("/api/connections")
    def get_connections(
        limit: int = 100,
        tool: str = "",
        decision: str = "",
        source: str = "",
        destination: str = "",
        authorization: str | None = Header(None),
    ) -> dict[str, Any]:
        """Return recent connections, optionally filtered."""
        user = check_auth(authorization)
        check_access(user, "stats")
        connections = gateway.get_connections(limit=500)
        # Apply filters
        if tool:
            connections = [c for c in connections if tool.lower() in c.get("tool", "").lower()]
        if decision:
            connections = [
                c for c in connections if decision.lower() in c.get("decision", "").lower()
            ]
        if source:
            connections = [c for c in connections if source.lower() in c.get("source", "").lower()]
        if destination:
            connections = [
                c for c in connections if destination.lower() in c.get("destination", "").lower()
            ]
        return {"connections": connections[:limit], "count": len(connections)}

    # --- Policy Management ---
    @app.get("/api/policies")
    def get_policies(
        file: str = "",
        authorization: str | None = Header(None),
    ) -> dict[str, Any]:
        """Get policy file content. If policy_dir is set, list all files."""
        user = check_auth(authorization)
        check_access(user, "policies")
        if gateway.config.policy_dir:
            pdir = Path(gateway.config.policy_dir)
            if not pdir.is_dir():
                return {"content": "", "files": [], "mode": "dir", "path": str(pdir)}
            files = sorted(pdir.glob("*.yaml"))
            file_list = [{"name": f.name, "path": str(f), "size": f.stat().st_size} for f in files]
            if file:
                # SECURITY: restrict file access to the policy directory only
                target = Path(file).resolve()
                if not str(target).startswith(str(pdir.resolve())):
                    raise HTTPException(403, "Access denied: file outside policy directory")
                if not target.is_file():
                    raise HTTPException(404, f"File not found: {Path(file).name}")
                content = target.read_text(encoding="utf-8")
            elif files:
                content = files[0].read_text(encoding="utf-8")
            else:
                content = ""
            return {"content": content, "files": file_list, "mode": "dir", "path": str(pdir)}
        else:
            policy_path = Path(gateway.config.policy_file)
            content = policy_path.read_text() if policy_path.exists() else ""
            return {
                "content": content,
                "files": [{"name": policy_path.name, "path": str(policy_path)}],
                "mode": "single",
                "path": str(policy_path),
            }

    @app.put("/api/policies")
    def update_policies(
        req: PolicyUpdateRequest, authorization: str | None = Header(None)
    ) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "policies")
        policy_path = Path(gateway.config.policy_file)
        policy_path.write_text(req.content, encoding="utf-8")
        result = gateway.reload_policies()
        return result

    @app.post("/api/policies/reload")
    def reload_policies(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "policies")
        return gateway.reload_policies()

    @app.post("/api/policies/validate")
    def validate_policy(
        req: PolicyUpdateRequest, authorization: str | None = Header(None)
    ) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "policies")
        try:
            import yaml

            from raucle.policy import PolicyFile

            data = yaml.safe_load(req.content)
            PolicyFile.from_dict(data)
            return {"valid": True}
        except Exception as exc:
            return {"valid": False, "error": str(exc)}

    # --- Receipts ---
    @app.get("/api/receipts")
    def get_receipts(limit: int = 50, authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "receipts")
        path = Path(gateway.config.receipt_store)
        if not path.exists():
            return {"receipts": [], "count": 0}
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        recent = lines[-limit:] if len(lines) > limit else lines
        receipts = []
        for line in recent:
            try:
                receipts.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return {"receipts": receipts, "count": len(receipts), "total": len(lines)}

    # --- SIEM Config ---
    @app.get("/api/siem")
    def get_siem_config(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "config")
        return {
            "enabled": gateway.siem.enabled,
            "backend": gateway.siem.backend,
            "url": gateway.siem.url,
            "token_configured": bool(gateway.siem.token),
            "buffered_events": len(gateway.siem.buffered_events()),
        }

    @app.put("/api/siem")
    def update_siem_config(
        req: SIEMConfigRequest, authorization: str | None = Header(None)
    ) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "config")
        gateway.config.siem_enabled = req.enabled
        gateway.config.siem_backend = req.backend
        gateway.config.siem_url = req.url
        gateway.config.siem_token = req.token
        gateway.siem.enabled = req.enabled
        gateway.siem.backend = req.backend
        gateway.siem.url = req.url
        gateway.siem.token = req.token
        return {"status": "ok"}

    # --- User Management (admin only) ---
    @app.get("/api/users")
    def list_users(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "users")
        return {
            "users": [
                {"api_key": u.api_key[:8] + "...", "role": u.role, "name": u.name}
                for u in users.list_users()
            ]
        }

    @app.post("/api/users")
    def create_user(
        req: UserCreateRequest, authorization: str | None = Header(None)
    ) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "users")
        if req.role not in ("admin", "operator", "auditor"):
            raise HTTPException(400, "role must be admin, operator, or auditor")
        new_user = users.add_user(req.api_key, req.role, req.name)
        return {"status": "ok", "api_key": new_user.api_key[:8] + "...", "role": new_user.role}

    @app.delete("/api/users/{api_key}")
    def delete_user(api_key: str, authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "users")
        if users.remove_user(api_key):
            return {"status": "ok"}
        raise HTTPException(404, "user not found")

    # --- Config ---
    @app.get("/api/config")
    def get_config(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "config")
        return {
            "signer_backend": gateway.config.signer_backend,
            "policy_file": gateway.config.policy_file,
            "receipt_store": gateway.config.receipt_store,
            "audit_chain": gateway.config.audit_chain,
            "compliance_framework": gateway.config.compliance_framework,
            "registry_path": gateway.config.registry_path,
            "gateway_port": gateway.config.port,
            "admin_port": gateway.config.admin_port,
        }

    # --- Admin Panel UI ---
    @app.get("/", response_class=HTMLResponse)
    def admin_panel() -> str:
        return ADMIN_PANEL_HTML

    return app


# ---------------------------------------------------------------------------
# Admin Panel HTML (inline, no build step required)
# ---------------------------------------------------------------------------


ADMIN_PANEL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Raucle Gateway</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    background: #fff; color: #171717; }
  .header { display: flex; align-items: center; justify-content: space-between;
    padding: 10px 24px; border-bottom: 1px solid #f0f0f0; position: sticky; top: 0; background: #fff; z-index: 40; }
  .header-left { display: flex; align-items: center; gap: 16px; }
  .logo { font-size: 18px; font-weight: 600; letter-spacing: -0.025em; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 999px;
    background: #f5f5f5; color: #737373; font-weight: 500; }
  .tabs { display: flex; gap: 2px; padding: 0 24px; border-bottom: 1px solid #f0f0f0; }
  .tab { padding: 10px 16px; cursor: pointer; color: #a3a3a3; font-size: 14px;
    border-bottom: 2px solid transparent; transition: all 0.15s; }
  .tab:hover { color: #525252; }
  .tab.active { color: #171717; border-bottom-color: #171717; }
  .content { max-width: 1400px; margin: 0 auto; padding: 24px; }
  .card { background: #fff; border: 1px solid #f0f0f0; border-radius: 12px;
    padding: 24px; margin-bottom: 16px; }
  .card-title { font-size: 13px; font-weight: 600; color: #737373;
    text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 16px; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; }
  .stat { text-align: center; padding: 16px 0; }
  .stat-value { font-size: 36px; font-weight: 700; letter-spacing: -0.03em; }
  .stat-label { font-size: 12px; color: #a3a3a3; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 8px 12px; font-size: 12px; font-weight: 600;
    color: #a3a3a3; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #f0f0f0; }
  td { padding: 10px 12px; font-size: 13px; border-bottom: 1px solid #f7f7f7; }
  tr:hover td { background: #fafafa; }
  .badge-allow { background: #171717; color: #fff; padding: 2px 10px; border-radius: 999px; font-size: 11px; font-weight: 500; }
  .badge-deny { background: #f5f5f5; color: #525252; padding: 2px 10px; border-radius: 999px; font-size: 11px; font-weight: 500; }
  .badge-escalate { background: #f5f5f5; color: #737373; padding: 2px 10px; border-radius: 999px; font-size: 11px; font-weight: 500; border: 1px solid #e5e5e5; }
  .btn { background: #171717; color: #fff; border: none; padding: 8px 20px;
    border-radius: 999px; cursor: pointer; font-size: 14px; font-weight: 500; transition: background 0.15s; }
  .btn:hover { background: #000; }
  .btn-secondary { background: #f5f5f5; color: #171717; }
  .btn-secondary:hover { background: #ebebeb; }
  .input { padding: 8px 14px; background: #fff; border: 1px solid #e5e5e5;
    border-radius: 999px; font-size: 14px; font-family: inherit; color: #171717;
    outline: none; transition: border-color 0.15s; }
  .input:focus { border-color: #171717; }
  select.input { border-radius: 999px; }
  textarea.input { border-radius: 12px; }
  .editor { width: 100%; height: 400px; background: #fafafa; color: #171717;
    border: 1px solid #e5e5e5; border-radius: 12px; padding: 16px;
    font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 13px; resize: vertical; }
  .editor:focus { outline: none; border-color: #171717; }
  .actions { display: flex; gap: 8px; margin-top: 16px; }
  .login { max-width: 360px; margin: 80px auto; }
  .login .input { width: 100%; margin-bottom: 12px; }
  .hidden { display: none; }
  pre { background: #fafafa; padding: 16px; border-radius: 12px; border: 1px solid #f0f0f0; overflow-x: auto; font-size: 13px; font-family: ui-monospace, "SF Mono", Menlo, monospace; }
  .toggle { display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 14px; color: #525252; }
  .toggle input { width: 16px; height: 16px; accent-color: #171717; }
  .live-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #22c55e; margin-right: 6px; animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
  .file-list { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
  .file-chip { padding: 4px 12px; border-radius: 999px; background: #f5f5f5; font-size: 12px; color: #525252; cursor: pointer; }
  .file-chip:hover { background: #ebebeb; }
  .file-chip.active { background: #171717; color: #fff; }

  /* === TRAFFIC FLOW (Netbird-style three-column) === */
  .flow-container { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0; min-height: 400px; }
  .flow-col { border: 1px solid #f0f0f0; display: flex; flex-direction: column; }
  .flow-col-header { padding: 12px 16px; font-size: 13px; font-weight: 600; color: #737373;
    text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #f0f0f0;
    display: flex; align-items: center; justify-content: space-between; background: #fafafa; }
  .flow-col-header .count { font-size: 11px; color: #a3a3a3; font-weight: 400; }
  .flow-col-body { flex: 1; overflow-y: auto; max-height: 350px; }
  .flow-item { padding: 10px 16px; border-bottom: 1px solid #f7f7f7; cursor: pointer; transition: all 0.15s; }
  .flow-item:hover { background: #f5f5f5; }
  .flow-item.active { background: #f0f0f0; border-left: 3px solid #171717; }
  .flow-item-name { font-size: 13px; font-weight: 500; color: #171717; }
  .flow-item-meta { font-size: 11px; color: #a3a3a3; margin-top: 2px; }
  .flow-item-bar { height: 3px; border-radius: 2px; margin-top: 6px; background: #f0f0f0; overflow: hidden; }
  .flow-item-bar-fill { height: 100%; border-radius: 2px; transition: width 0.3s; }
  .flow-center-pipeline { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 24px; gap: 12px; }
  .flow-pipeline-node { border: 1px solid #e5e5e5; border-radius: 12px; padding: 12px 20px; text-align: center; background: #fff; min-width: 160px; }
  .flow-pipeline-label { font-size: 11px; color: #a3a3a3; text-transform: uppercase; letter-spacing: 0.05em; }
  .flow-pipeline-value { font-size: 14px; font-weight: 600; margin-top: 4px; }
  .flow-pipeline-decision { font-size: 12px; font-weight: 600; margin-top: 4px; }
  .flow-arrow-icon { color: #d4d4d4; font-size: 18px; }
  .flow-col-filter { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; }
  .flow-col-filter input { width: 100%; font-size: 12px; padding: 6px 10px; }
  .flow-empty { text-align: center; padding: 40px 16px; color: #a3a3a3; font-size: 13px; }
  .direction-badge { font-size: 10px; padding: 1px 6px; border-radius: 4px; font-weight: 500; margin-left: 6px; }
  .dir-inbound { background: #eff6ff; color: #2563eb; }
  .dir-outbound { background: #f0fdf4; color: #16a34a; }

  /* Connection log table */
  .conn-table { max-height: 400px; overflow-y: auto; }
  .conn-row { cursor: pointer; }
  .conn-row.selected td { background: #f5f5f5; }
  .filter-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }

  /* Direction toggle (Netbird style) */
  .dir-toggle { display: inline-flex; background: #f5f5f5; border-radius: 8px; padding: 2px; gap: 2px; }
  .dir-toggle button { border: none; background: transparent; padding: 6px 14px; font-size: 13px; border-radius: 6px; cursor: pointer; color: #737373; font-family: inherit; }
  .dir-toggle button.active { background: #fff; color: #171717; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
</style>
</head>
<body>
<div class="header">
  <div class="header-left">
    <div class="logo">Raucle</div>
    <span class="badge">Gateway</span>
  </div>
</div>

<div id="login" class="content login">
  <div class="card">
    <div class="card-title">Sign In</div>
    <input class="input" id="apiKey" type="password" placeholder="API Key" onkeydown="if(event.key==='Enter')login()">
    <button class="btn" style="width:100%" onclick="login()">Sign In</button>
  </div>
</div>

<div id="main" class="hidden">
  <div class="tabs">
    <div class="tab active" onclick="showTab('dashboard',this)">Dashboard</div>
    <div class="tab" onclick="showTab('connections',this)">Connections</div>
    <div class="tab" onclick="showTab('policies',this)">Policies</div>
    <div class="tab" onclick="showTab('receipts',this)">Receipts</div>
    <div class="tab" onclick="showTab('siem',this)">SIEM</div>
    <div class="tab" onclick="showTab('users',this)">Users</div>
    <div class="tab" onclick="showTab('config',this)">Config</div>
  </div>
  <div class="content">

    <!-- DASHBOARD -->
    <div id="tab-dashboard">
      <div class="card"><div class="card-title">Gate Decisions</div>
        <div class="stats-grid" id="statsGrid"></div>
      </div>
      <div class="card"><div class="card-title">By Tool</div>
        <table><thead><tr><th>Tool</th><th>Allowed</th><th>Denied</th><th>Escalated</th></tr></thead>
        <tbody id="toolTableBody"></tbody></table>
      </div>
    </div>

    <!-- CONNECTIONS (Netbird-style three-column flow) -->
    <div id="tab-connections" class="hidden">
      <div class="card">
        <div class="card-title"><span class="live-dot"></span>Traffic Flow</div>
        <div class="filter-bar">
          <div class="dir-toggle">
            <button class="active" onclick="setDirFilter('all',this)">All</button>
            <button onclick="setDirFilter('inbound',this)">Inbound</button>
            <button onclick="setDirFilter('outbound',this)">Outbound</button>
          </div>
          <select class="input" id="filterDecision">
            <option value="">All Decisions</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="escalate">Escalate</option>
          </select>
          <input class="input" id="filterTool" placeholder="Filter by tool...">
          <label class="toggle"><input type="checkbox" id="liveMode" checked onchange="loadConnections()"> Live</label>
        </div>
        <div class="flow-container" id="flowContainer">
          <!-- Left: Inbound Sources -->
          <div class="flow-col">
            <div class="flow-col-header">Inbound Sources <span class="count" id="srcCount">0</span></div>
            <div class="flow-col-filter"><input class="input" id="srcFilter" placeholder="Filter sources..." oninput="renderFlowColumns()"></div>
            <div class="flow-col-body" id="srcList"></div>
          </div>
          <!-- Center: Gate Processing -->
          <div class="flow-col" style="border-left: 2px solid #f0f0f0; border-right: 2px solid #f0f0f0;">
            <div class="flow-col-header">Gate Processing <span class="count" id="midCount">0</span></div>
            <div class="flow-col-filter"><input class="input" id="midFilter" placeholder="Filter by tool or policy..." oninput="renderFlowColumns()"></div>
            <div class="flow-col-body" id="midList"></div>
          </div>
          <!-- Right: Outbound Destinations -->
          <div class="flow-col">
            <div class="flow-col-header">Outbound Destinations <span class="count" id="dstCount">0</span></div>
            <div class="flow-col-filter"><input class="input" id="dstFilter" placeholder="Filter destinations..." oninput="renderFlowColumns()"></div>
            <div class="flow-col-body" id="dstList"></div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Connection Log</div>
        <div class="conn-table">
          <table><thead><tr><th>Time</th><th>Source</th><th>Tool</th><th>Policy</th><th>Decision</th><th>Destination</th><th>Reason</th><th>Latency</th></tr></thead>
          <tbody id="connBody"></tbody></table>
        </div>
      </div>
    </div>

    <!-- POLICIES -->
    <div id="tab-policies" class="hidden">
      <div class="card">
        <div class="card-title">Policy Files</div>
        <div class="file-list" id="fileList"></div>
        <textarea class="editor" id="policyEditor"></textarea>
        <div class="actions">
          <button class="btn" onclick="validatePolicy()">Validate</button>
          <button class="btn" onclick="savePolicy()">Save & Deploy</button>
          <button class="btn btn-secondary" onclick="reloadPolicy()">Reload</button>
        </div>
      </div>
    </div>

    <!-- RECEIPTS -->
    <div id="tab-receipts" class="hidden">
      <div class="card"><div class="card-title">Recent Receipts</div><pre id="receiptsView">Loading...</pre></div>
    </div>

    <!-- SIEM -->
    <div id="tab-siem" class="hidden">
      <div class="card">
        <div class="card-title">SIEM Forwarding</div>
        <label class="toggle" style="margin-bottom:16px"><input type="checkbox" id="siemEnabled"> Enabled</label>
        <div style="display:flex;flex-direction:column;gap:8px;max-width:400px">
          <input class="input" id="siemBackend" placeholder="splunk / elastic / sentinel">
          <input class="input" id="siemUrl" placeholder="SIEM endpoint URL">
          <input class="input" id="siemToken" type="password" placeholder="SIEM token">
        </div>
        <div class="actions"><button class="btn" onclick="saveSIEM()">Save</button></div>
      </div>
    </div>

    <!-- USERS -->
    <div id="tab-users" class="hidden">
      <div class="card">
        <div class="card-title">Add User</div>
        <div style="display:flex;flex-direction:column;gap:8px;max-width:400px">
          <input class="input" id="newKey" placeholder="API Key">
          <input class="input" id="newRole" placeholder="admin / operator / auditor">
          <input class="input" id="newName" placeholder="Name">
        </div>
        <div class="actions"><button class="btn" onclick="addUser()">Add</button></div>
      </div>
      <div class="card"><div class="card-title">Users</div>
        <table><thead><tr><th>Key</th><th>Role</th><th>Name</th></tr></thead>
        <tbody id="userTableBody"></tbody></table>
      </div>
    </div>

    <!-- CONFIG -->
    <div id="tab-config" class="hidden">
      <div class="card"><div class="card-title">Configuration</div><pre id="configView"></pre></div>
    </div>

  </div>
</div>

<script>
let key = '';
let connPollId = null;
let allConns = [];
let dirFilter = 'all';
let selectedSource = null;
let selectedDest = null;

function login() {
  key = document.getElementById('apiKey').value;
  fetch('/api/stats', {headers: {'Authorization': key}})
    .then(r => { if (r.ok) { document.getElementById('login').classList.add('hidden');
      document.getElementById('main').classList.remove('hidden'); loadAll(); }
      else { alert('Invalid API key'); } });
}

function showTab(t, el) {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('[id^=tab-]').forEach(x => x.classList.add('hidden'));
  el.classList.add('active');
  document.getElementById('tab-' + t).classList.remove('hidden');
  if (t === 'dashboard') loadStats();
  if (t === 'connections') { loadConnections(); startConnPolling(); }
  else { stopConnPolling(); }
  if (t === 'policies') loadPolicy();
  if (t === 'receipts') loadReceipts();
  if (t === 'siem') loadSIEM();
  if (t === 'users') loadUsers();
  if (t === 'config') loadConfig();
}

function api(path, opts) {
  return fetch(path, {...(opts||{}), headers: {'Authorization': key, ...((opts||{}).headers||{})}});
}

function loadAll() { loadStats(); }

function loadStats() {
  api('/api/stats').then(r=>r.json()).then(d=>{
    document.getElementById('statsGrid').innerHTML =
      `<div class="stat"><div class="stat-value">${d.total_requests||0}</div><div class="stat-label">Total</div></div>` +
      `<div class="stat"><div class="stat-value">${d.allowed||0}</div><div class="stat-label">Allowed</div></div>` +
      `<div class="stat"><div class="stat-value">${d.denied||0}</div><div class="stat-label">Denied</div></div>` +
      `<div class="stat"><div class="stat-value">${d.escalated||0}</div><div class="stat-label">Escalated</div></div>` +
      `<div class="stat"><div class="stat-value">${d.avg_latency_us||0}</div><div class="stat-label">Avg us</div></div>`;
    let tb = document.getElementById('toolTableBody'); tb.innerHTML='';
    Object.entries(d.tools||{}).forEach(([t,s])=>tb.innerHTML+=`<tr><td>${esc(t)}</td><td>${s.allow||0}</td><td>${s.deny||0}</td><td>${s.escalate||0}</td></tr>`);
  });
}

function esc(s) { return s ? s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])) : '--'; }

function setDirFilter(d, el) {
  dirFilter = d;
  document.querySelectorAll('.dir-toggle button').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  loadConnections();
}

// === CONNECTIONS (Netbird-style three-column flow) ===
function loadConnections() {
  let params = new URLSearchParams({limit: 500});
  let fd = document.getElementById('filterDecision').value;
  let ft = document.getElementById('filterTool').value;
  if (fd) params.set('decision', fd);
  if (ft) params.set('tool', ft);
  api('/api/connections?' + params.toString()).then(r=>r.json()).then(d=>{
    allConns = d.connections || [];
    renderFlowColumns();
    renderConnTable();
  }).catch(()=>{});
}

function getFilteredConns() {
  let fd = document.getElementById('filterDecision').value;
  let ft = document.getElementById('filterTool').value.toLowerCase();
  let conns = allConns;
  if (fd) conns = conns.filter(c => c.decision === fd);
  if (ft) conns = conns.filter(c => (c.tool||'').toLowerCase().includes(ft));
  if (selectedSource) conns = conns.filter(c => c.source === selectedSource);
  if (selectedDest) conns = conns.filter(c => c.destination === selectedDest);
  return conns;
}

function renderFlowColumns() {
  let conns = getFilteredConns();
  let sf = (document.getElementById('srcFilter')?.value || '').toLowerCase();
  let mf = (document.getElementById('midFilter')?.value || '').toLowerCase();
  let df = (document.getElementById('dstFilter')?.value || '').toLowerCase();

  // Group by source
  let bySource = {};
  conns.forEach(c => {
    let s = c.source || 'unknown';
    if (dirFilter === 'outbound') return; // inbound column shows sources
    if (sf && !s.toLowerCase().includes(sf)) return;
    if (!bySource[s]) bySource[s] = { total: 0, allow: 0, deny: 0, escalate: 0, conns: [] };
    bySource[s].total++;
    bySource[s][c.decision] = (bySource[s][c.decision]||0) + 1;
    bySource[s].conns.push(c);
  });

  // Group by destination
  let byDest = {};
  conns.forEach(c => {
    let d = c.destination || 'unknown';
    if (dirFilter === 'inbound') return; // outbound column shows destinations
    if (df && !d.toLowerCase().includes(df)) return;
    if (!byDest[d]) byDest[d] = { total: 0, allow: 0, deny: 0, escalate: 0, conns: [] };
    byDest[d].total++;
    byDest[d][c.decision] = (byDest[d][c.decision]||0) + 1;
    byDest[d].conns.push(c);
  });

  // Group by tool/policy (center column)
  let byTool = {};
  conns.forEach(c => {
    let t = c.tool || 'unknown';
    let p = c.policy || '';
    if (mf && !t.toLowerCase().includes(mf) && !(p||'').toLowerCase().includes(mf)) return;
    if (!byTool[t]) byTool[t] = { total: 0, allow: 0, deny: 0, escalate: 0, policy: p, conns: [] };
    byTool[t].total++;
    byTool[t][c.decision] = (byTool[t][c.decision]||0) + 1;
    byTool[t].conns.push(c);
  });

  // Render source column
  let srcHTML = '';
  let srcEntries = Object.entries(bySource).sort((a,b) => b[1].total - a[1].total);
  document.getElementById('srcCount').textContent = srcEntries.length;
  if (srcEntries.length === 0) {
    srcHTML = '<div class="flow-empty">No inbound sources</div>';
  } else {
    srcEntries.forEach(([name, data]) => {
      let pct = Math.round(data.allow / data.total * 100);
      let isActive = selectedSource === name;
      srcHTML += `<div class="flow-item${isActive?' active':''}" onclick="toggleSource('${esc(name)}')">
        <div class="flow-item-name">${esc(name)} <span class="direction-badge dir-inbound">in</span></div>
        <div class="flow-item-meta">${data.total} calls - ${data.allow||0} allow / ${data.deny||0} deny / ${data.escalate||0} escalate</div>
        <div class="flow-item-bar"><div class="flow-item-bar-fill" style="width:${pct}%;background:#171717"></div></div>
      </div>`;
    });
  }
  document.getElementById('srcList').innerHTML = srcHTML;

  // Render center (gate processing) column
  let midHTML = '';
  let midEntries = Object.entries(byTool).sort((a,b) => b[1].total - a[1].total);
  document.getElementById('midCount').textContent = midEntries.length;
  if (midEntries.length === 0) {
    midHTML = '<div class="flow-empty">No gate activity</div>';
  } else {
    midEntries.forEach(([name, data]) => {
      let pct = Math.round(data.allow / data.total * 100);
      let policy = data.policy ? data.policy.split('/').pop() : '';
      midHTML += `<div class="flow-item" onclick="filterByTool('${esc(name)}')">
        <div class="flow-item-name">${esc(name)}</div>
        <div class="flow-item-meta">${data.total} calls - ${data.allow||0} allow / ${data.deny||0} deny / ${data.escalate||0} escalate</div>
        ${policy ? `<div class="flow-item-meta">policy: ${esc(policy)}</div>` : ''}
        <div class="flow-item-bar"><div class="flow-item-bar-fill" style="width:${pct}%;background:#171717"></div></div>
      </div>`;
    });
  }
  document.getElementById('midList').innerHTML = midHTML;

  // Render destination column
  let dstHTML = '';
  let dstEntries = Object.entries(byDest).sort((a,b) => b[1].total - a[1].total);
  document.getElementById('dstCount').textContent = dstEntries.length;
  if (dstEntries.length === 0) {
    dstHTML = '<div class="flow-empty">No outbound destinations</div>';
  } else {
    dstEntries.forEach(([name, data]) => {
      let pct = Math.round(data.allow / data.total * 100);
      let isActive = selectedDest === name;
      dstHTML += `<div class="flow-item${isActive?' active':''}" onclick="toggleDest('${esc(name)}')">
        <div class="flow-item-name">${esc(name)} <span class="direction-badge dir-outbound">out</span></div>
        <div class="flow-item-meta">${data.total} calls - ${data.allow||0} allow / ${data.deny||0} deny / ${data.escalate||0} escalate</div>
        <div class="flow-item-bar"><div class="flow-item-bar-fill" style="width:${pct}%;background:#171717"></div></div>
      </div>`;
    });
  }
  document.getElementById('dstList').innerHTML = dstHTML;
}

function toggleSource(name) {
  selectedSource = selectedSource === name ? null : name;
  renderFlowColumns();
  renderConnTable();
}

function toggleDest(name) {
  selectedDest = selectedDest === name ? null : name;
  renderFlowColumns();
  renderConnTable();
}

function filterByTool(tool) {
  document.getElementById('filterTool').value = tool;
  loadConnections();
}

function renderConnTable() {
  let conns = getFilteredConns();
  let tb = document.getElementById('connBody');
  tb.innerHTML = '';
  conns.forEach((c,i) => {
    let badge = c.decision === 'allow' ? 'badge-allow' : c.decision === 'deny' ? 'badge-deny' : 'badge-escalate';
    let time = c.timestamp ? c.timestamp.substring(11,19) : '--:--:--';
    let policy = c.policy ? c.policy.split('/').pop() : '--';
    tb.innerHTML += `<tr class="conn-row" onclick="selectConn(${i})" data-idx="${i}">
      <td>${esc(time)}</td><td>${esc(c.source)}</td><td>${esc(c.tool)}</td>
      <td>${esc(policy)}</td><td><span class="${badge}">${esc(c.decision)}</span></td>
      <td>${esc(c.destination)}</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(c.reason)}</td>
      <td>${c.latency_us||0}us</td></tr>`;
  });
}

function selectConn(idx) {
  document.querySelectorAll('.conn-row').forEach(r => r.classList.remove('selected'));
  let row = document.querySelector(`.conn-row[data-idx="${idx}"]`);
  if (row) row.classList.add('selected');
}

function startConnPolling() {
  stopConnPolling();
  connPollId = setInterval(() => {
    if (document.getElementById('liveMode')?.checked && !document.getElementById('tab-connections').classList.contains('hidden')) { loadConnections(); }
  }, 3000);
}
function stopConnPolling() { if (connPollId) { clearInterval(connPollId); connPollId = null; } }

// --- POLICIES ---
let currentFile = '';
function loadPolicy() {
  api('/api/policies').then(r=>r.json()).then(d=>{
    let fl = document.getElementById('fileList');
    fl.innerHTML = '';
    (d.files||[]).forEach(f => {
      let chip = document.createElement('div');
      chip.className = 'file-chip' + (f.name === currentFile || (!currentFile && f === d.files[0]) ? ' active' : '');
      chip.textContent = f.name;
      chip.onclick = () => { currentFile = f.name; loadPolicyFile(f.path); document.querySelectorAll('.file-chip').forEach(c=>c.classList.remove('active')); chip.classList.add('active'); };
      fl.appendChild(chip);
    });
    if (d.content !== undefined) { document.getElementById('policyEditor').value = d.content; }
  });
}
function loadPolicyFile(path) {
  api('/api/policies?file=' + encodeURIComponent(path)).then(r=>r.json()).then(d=>{ document.getElementById('policyEditor').value = d.content || ''; });
}
function validatePolicy() {
  api('/api/policies/validate',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({content:document.getElementById('policyEditor').value})})
    .then(r=>r.json()).then(d=>alert(d.valid?'Valid':'Invalid: '+d.error));
}
function savePolicy() {
  api('/api/policies',{method:'PUT',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({content:document.getElementById('policyEditor').value})})
    .then(r=>r.json()).then(d=>alert('Saved: '+JSON.stringify(d)));
}
function reloadPolicy() { api('/api/policies/reload',{method:'POST'}).then(r=>r.json()).then(d=>alert('Reloaded: '+JSON.stringify(d))); }

function loadReceipts() { api('/api/receipts?limit=20').then(r=>r.json()).then(d=>{ document.getElementById('receiptsView').textContent=JSON.stringify(d.receipts,null,2); }); }
function loadSIEM() { api('/api/siem').then(r=>r.json()).then(d=>{ document.getElementById('siemEnabled').checked=d.enabled; document.getElementById('siemBackend').value=d.backend||''; document.getElementById('siemUrl').value=d.url||''; }); }
function saveSIEM() { api('/api/siem',{method:'PUT',headers:{'Content-Type':'application/json'}, body:JSON.stringify({enabled:document.getElementById('siemEnabled').checked, backend:document.getElementById('siemBackend').value, url:document.getElementById('siemUrl').value, token:document.getElementById('siemToken').value})}).then(r=>r.json()).then(d=>alert('Saved')); }
function loadUsers() { api('/api/users').then(r=>r.json()).then(d=>{ let tb=document.getElementById('userTableBody');tb.innerHTML=''; d.users.forEach(u=>tb.innerHTML+=`<tr><td>${esc(u.api_key)}</td><td>${esc(u.role)}</td><td>${esc(u.name)}</td></tr>`); }); }
function addUser() { api('/api/users',{method:'POST',headers:{'Content-Type':'application/json'}, body:JSON.stringify({api_key:document.getElementById('newKey').value, role:document.getElementById('newRole').value, name:document.getElementById('newName').value})}).then(r=>r.json()).then(d=>{alert('Added');loadUsers();}); }
function loadConfig() { api('/api/config').then(r=>r.json()).then(d=>{ document.getElementById('configView').textContent=JSON.stringify(d,null,2); }); }

setInterval(()=>{if(!document.getElementById('main').classList.contains('hidden') && !document.getElementById('tab-dashboard').classList.contains('hidden'))loadStats();},5000);
</script>
</body>
</html>"""


__all__ = ["create_gateway_app", "create_admin_app"]
