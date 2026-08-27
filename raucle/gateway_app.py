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
  *,*::before,*::after { margin:0; padding:0; box-sizing:border-box; border:0 solid; }
  :host,html { line-height:1.5; font-family:ui-sans-serif,system-ui,-apple-system,sans-serif; font-feature-settings:normal; -webkit-tap-highlight-color:transparent; }
  body { background:#fff; color:#171717; line-height:inherit; }
  a { color:inherit; text-decoration:inherit; }
  button { cursor:pointer; font-family:inherit; }
  code,pre { font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; }

  /* Layout */
  .wrap { max-width:1024px; margin:0 auto; padding:0 24px; }
  .nav { border-bottom:1px solid #e5e5e5; padding:12px 0; }
  .nav-inner { display:flex; align-items:center; gap:12px; max-width:1024px; margin:0 auto; padding:0 24px; }
  .nav-brand { font-size:16px; font-weight:600; letter-spacing:-0.025em; }
  .nav-badge { background:#171717; color:#fff; padding:2px 8px; border-radius:9999px; font-size:11px; font-weight:500; }
  .nav-right { margin-left:auto; display:flex; gap:8px; align-items:center; }

  .tabs { display:flex; gap:0; border-bottom:1px solid #e5e5e5; }
  .tab { padding:10px 16px; cursor:pointer; color:#737373; font-size:14px; border-bottom:2px solid transparent; }
  .tab:hover { color:#404040; }
  .tab.active { color:#171717; border-bottom-color:#171717; font-weight:500; }

  .section { padding:24px; }
  .hidden { display:none !important; }

  /* Cards */
  .card { border:1px solid #e5e5e5; border-radius:12px; padding:20px; margin-bottom:20px; background:#fff; }
  .card-title { font-size:13px; font-weight:600; color:#737373; text-transform:uppercase; letter-spacing:0.025em; margin-bottom:16px; }

  /* Stats */
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:16px; }
  .stat { text-align:center; padding:16px; }
  .stat-num { font-size:32px; font-weight:600; letter-spacing:-0.025em; }
  .stat-lbl { font-size:12px; color:#737373; margin-top:4px; }
  .stat.allow .stat-num { color:#16a34a; }
  .stat.deny .stat-num { color:#dc2626; }
  .stat.esc .stat-num { color:#ca8a04; }

  /* Table */
  table { width:100%; border-collapse:collapse; }
  th { text-align:left; padding:8px 12px; font-size:11px; font-weight:600; color:#737373; text-transform:uppercase; border-bottom:1px solid #e5e5e5; }
  td { padding:8px 12px; font-size:13px; border-bottom:1px solid #f5f5f5; }
  tr:hover { background:#fafafa; }

  /* Badges */
  .badge { padding:2px 8px; border-radius:9999px; font-size:11px; font-weight:500; }
  .badge-allow { background:#dcfce7; color:#16a34a; }
  .badge-deny { background:#fee2e2; color:#dc2626; }
  .badge-esc { background:#fef9c3; color:#ca8a04; }

  /* Flow viz */
  .flow { display:flex; align-items:center; justify-content:center; gap:0; padding:24px 0; flex-wrap:wrap; }
  .flow-node { border:1px solid #e5e5e5; border-radius:12px; padding:16px 24px; min-width:140px; text-align:center; background:#fff; }
  .flow-node.src { border-color:#d1d5db; }
  .flow-node.gate { border-color:#9ca3af; }
  .flow-node.dst { border-color:#d1d5db; }
  .flow-lbl { font-size:10px; color:#737373; text-transform:uppercase; margin-bottom:6px; }
  .flow-val { font-size:15px; font-weight:500; }
  .flow-arrow { color:#a3a3a3; font-size:24px; padding:0 12px; }
  .flow-dec { font-size:11px; font-weight:500; padding:3px 8px; border-radius:9999px; margin-top:8px; display:inline-block; }

  /* Forms */
  input,select,textarea { font-family:inherit; font-size:14px; padding:8px 12px; border:1px solid #d4d4d4; border-radius:8px; background:#fff; color:#171717; outline:none; }
  input:focus,select:focus,textarea:focus { border-color:#171717; }
  textarea.editor { width:100%; height:400px; font-family:ui-monospace,monospace; font-size:13px; resize:vertical; border-radius:8px; }
  .btn { background:#171717; color:#fff; border:none; padding:8px 20px; border-radius:9999px; font-size:14px; font-weight:500; }
  .btn:hover { background:#404040; }
  .btn.sec { background:#fff; color:#171717; border:1px solid #d4d4d4; }
  .btn.sec:hover { background:#f5f5f5; }
  .actions { display:flex; gap:8px; margin-top:12px; }
  .filters { display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; align-items:center; }

  /* Login */
  .login-card { max-width:400px; margin:80px auto; }
  .login-card input { width:100%; margin-bottom:12px; }

  /* Misc */
  pre { background:#f5f5f5; padding:16px; border-radius:8px; overflow-x:auto; font-size:12px; line-height:1.6; }
  .live-dot { display:inline-block; width:7px; height:7px; border-radius:50%; background:#16a34a; margin-right:6px; animation:pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
  .toggle { display:flex; align-items:center; gap:6px; font-size:13px; cursor:pointer; }
  .toggle input { width:14px; height:14px; }
  .conn-scroll { max-height:400px; overflow-y:auto; }
  .conn-row { cursor:pointer; }
  .conn-row.sel { background:#f0f0f0; }
  .timestamp { text-align:center; color:#737373; font-size:12px; margin-top:8px; }
</style>
</head>
<body>
<nav class="nav">
  <div class="nav-inner">
    <span class="nav-brand">Raucle</span>
    <span class="nav-badge">Gateway</span>
    <div class="nav-right" id="navRight"></div>
  </div>
</nav>

<div class="tabs">
  <div class="tab active" onclick="showTab('dashboard',this)">Dashboard</div>
  <div class="tab" onclick="showTab('connections',this)">Connections</div>
  <div class="tab" onclick="showTab('policies',this)">Policies</div>
  <div class="tab" onclick="showTab('receipts',this)">Receipts</div>
  <div class="tab" onclick="showTab('siem',this)">SIEM</div>
  <div class="tab" onclick="showTab('users',this)">Users</div>
  <div class="tab" onclick="showTab('config',this)">Config</div>
</div>

<!-- LOGIN -->
<div id="login" class="wrap">
  <div class="card login-card">
    <div class="card-title">Authentication</div>
    <input type="password" id="apiKey" placeholder="API Key" onkeydown="if(event.key==='Enter')login()">
    <button class="btn" onclick="login()" style="width:100%">Login</button>
  </div>
</div>

<!-- MAIN -->
<div id="main" class="hidden">

  <!-- DASHBOARD -->
  <div id="tab-dashboard" class="wrap section">
    <div class="card"><div class="card-title">Gate Decisions</div>
      <div class="stats" id="statsGrid"></div>
    </div>
    <div class="card"><div class="card-title">By Tool</div>
      <table id="toolTable"><thead><tr><th>Tool</th><th>Allow</th><th>Deny</th><th>Escalate</th></tr></thead><tbody></tbody></table>
    </div>
  </div>

  <!-- CONNECTIONS -->
  <div id="tab-connections" class="wrap section hidden">
    <div class="card">
      <div class="card-title"><span class="live-dot"></span>Live Connection Flow</div>
      <div class="flow" id="flowViz">
        <div class="flow-node src"><div class="flow-lbl">Source</div><div class="flow-val" id="flowSrc">--</div></div>
        <div class="flow-arrow">&#8594;</div>
        <div class="flow-node gate"><div class="flow-lbl">Policy</div><div class="flow-val" id="flowPolicy">--</div><div class="flow-dec" id="flowDec">--</div></div>
        <div class="flow-arrow">&#8594;</div>
        <div class="flow-node dst"><div class="flow-lbl">Destination</div><div class="flow-val" id="flowDst">--</div></div>
      </div>
      <div class="timestamp" id="flowTime">No connections yet</div>
    </div>
    <div class="card">
      <div class="card-title">Connection Log</div>
      <div class="filters">
        <select id="fDec"><option value="">All</option><option value="allow">Allow</option><option value="deny">Deny</option><option value="escalate">Escalate</option></select>
        <input id="fTool" placeholder="Tool" style="min-width:100px">
        <input id="fSrc" placeholder="Source" style="min-width:100px">
        <input id="fDst" placeholder="Destination" style="min-width:100px">
        <button class="btn sec" onclick="clearFilters()">Clear</button>
        <label class="toggle"><input type="checkbox" id="liveMode" checked onchange="loadConns()"> Live</label>
      </div>
      <div class="conn-scroll">
        <table><thead><tr><th>Time</th><th>Source</th><th>Tool</th><th>Policy</th><th>Decision</th><th>Destination</th><th>Reason</th><th>Latency</th></tr></thead>
        <tbody id="connBody"></tbody></table>
      </div>
    </div>
  </div>

  <!-- POLICIES -->
  <div id="tab-policies" class="wrap section hidden">
    <div class="card"><div class="card-title">Policy File</div>
      <textarea class="editor" id="policyEditor"></textarea>
      <div class="actions">
        <button class="btn" onclick="validatePolicy()">Validate</button>
        <button class="btn" onclick="savePolicy()">Save & Deploy</button>
        <button class="btn sec" onclick="reloadPolicy()">Reload</button>
      </div>
    </div>
  </div>

  <!-- RECEIPTS -->
  <div id="tab-receipts" class="wrap section hidden">
    <div class="card"><div class="card-title">Recent Receipts</div><pre id="receiptsView">Loading...</pre></div>
  </div>

  <!-- SIEM -->
  <div id="tab-siem" class="wrap section hidden">
    <div class="card"><div class="card-title">SIEM Forwarding</div>
      <label class="toggle" style="margin-bottom:16px"><input type="checkbox" id="siemEnabled"> Enabled</label>
      <div style="display:flex;flex-direction:column;gap:8px;max-width:400px">
        <input id="siemBackend" placeholder="splunk / elastic / sentinel">
        <input id="siemUrl" placeholder="SIEM endpoint URL">
        <input type="password" id="siemToken" placeholder="SIEM token">
      </div>
      <div class="actions"><button class="btn" onclick="saveSIEM()">Save</button></div>
    </div>
  </div>

  <!-- USERS -->
  <div id="tab-users" class="wrap section hidden">
    <div class="card"><div class="card-title">Add User</div>
      <div style="display:flex;flex-direction:column;gap:8px;max-width:400px">
        <input id="newKey" placeholder="API Key">
        <input id="newRole" placeholder="admin / operator / auditor">
        <input id="newName" placeholder="Name">
      </div>
      <div class="actions"><button class="btn" onclick="addUser()">Add</button></div>
    </div>
    <div class="card"><div class="card-title">Users</div>
      <table id="userTable"><thead><tr><th>Key</th><th>Role</th><th>Name</th></tr></thead><tbody></tbody></table>
    </div>
  </div>

  <!-- CONFIG -->
  <div id="tab-config" class="wrap section hidden">
    <div class="card"><div class="card-title">Configuration</div><pre id="configView"></pre></div>
  </div>
</div>

<script>
let key='';
let pollId=null;
function esc(s){return s?s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])):'--';}
function api(p,o){return fetch(p,{...(o||{}),headers:{'Authorization':key,...((o||{}).headers||{})}});}
function login(){
  key=document.getElementById('apiKey').value;
  api('/api/stats').then(r=>{if(r.ok){document.getElementById('login').classList.add('hidden');document.getElementById('main').classList.remove('hidden');loadAll();}else{alert('Invalid key');}});
}
function showTab(t,el){
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('[id^=tab-]').forEach(x=>x.classList.add('hidden'));
  el.classList.add('active');
  document.getElementById('tab-'+t).classList.remove('hidden');
  if(t==='dashboard')loadStats();
  if(t==='connections'){loadConns();startPoll();}
  else{stopPoll();}
  if(t==='policies')loadPolicy();
  if(t==='receipts')loadReceipts();
  if(t==='siem')loadSIEM();
  if(t==='users')loadUsers();
  if(t==='config')loadConfig();
}
function loadAll(){loadStats();}
function loadStats(){
  api('/api/stats').then(r=>r.json()).then(d=>{
    document.getElementById('statsGrid').innerHTML=
      '<div class="stat"><div class="stat-num">'+d.total_requests+'</div><div class="stat-lbl">Total</div></div>'+
      '<div class="stat allow"><div class="stat-num">'+d.allowed+'</div><div class="stat-lbl">Allowed</div></div>'+
      '<div class="stat deny"><div class="stat-num">'+d.denied+'</div><div class="stat-lbl">Denied</div></div>'+
      '<div class="stat esc"><div class="stat-num">'+d.escalated+'</div><div class="stat-lbl">Escalated</div></div>'+
      '<div class="stat"><div class="stat-num">'+(d.avg_latency_us||0)+'</div><div class="stat-lbl">Avg us</div></div>';
    let tb=document.querySelector('#toolTable tbody');tb.innerHTML='';
    Object.entries(d.tools||{}).forEach(([t,s])=>tb.innerHTML+='<tr><td>'+esc(t)+'</td><td>'+(s.allow||0)+'</td><td>'+(s.deny||0)+'</td><td>'+(s.escalate||0)+'</td></tr>');
  });
}
function loadConns(){
  let p=new URLSearchParams({limit:200});
  let fd=document.getElementById('fDec').value,ft=document.getElementById('fTool').value,fs=document.getElementById('fSrc').value,fde=document.getElementById('fDst').value;
  if(fd)p.set('decision',fd);if(ft)p.set('tool',ft);if(fs)p.set('source',fs);if(fde)p.set('destination',fde);
  api('/api/connections?'+p.toString()).then(r=>r.json()).then(d=>{
    let tb=document.getElementById('connBody');tb.innerHTML='';
    (d.connections||[]).forEach((c,i)=>{
      let b=c.decision==='allow'?'badge-allow':c.decision==='deny'?'badge-deny':'badge-esc';
      let t=c.timestamp?c.timestamp.substring(11,19):'--:--:--';
      let pol=c.policy?c.policy.split('/').pop():'--';
      tb.innerHTML+='<tr class="conn-row" onclick="selConn('+i+')" data-idx="'+i+'"><td>'+esc(t)+'</td><td>'+esc(c.source)+'</td><td>'+esc(c.tool)+'</td><td>'+esc(pol)+'</td><td><span class="'+b+'">'+esc(c.decision)+'</span></td><td>'+esc(c.destination)+'</td><td style="max-width:180px;overflow:hidden;text-overflow:ellipsis">'+esc(c.reason)+'</td><td>'+(c.latency_us||0)+'us</td></tr>';
    });
    if(d.connections&&d.connections.length>0)updateFlow(d.connections[0]);
    window._conns=d.connections||[];
  }).catch(()=>{});
}
function selConn(i){
  document.querySelectorAll('.conn-row').forEach(r=>r.classList.remove('sel'));
  let r=document.querySelector('.conn-row[data-idx="'+i+'"]');if(r)r.classList.add('sel');
  if(window._conns&&window._conns[i])updateFlow(window._conns[i]);
}
function updateFlow(c){
  document.getElementById('flowSrc').textContent=esc(c.source);
  document.getElementById('flowDst').textContent=esc(c.destination);
  document.getElementById('flowPolicy').textContent=esc(c.policy?c.policy.split('/').pop():c.tool);
  let d=document.getElementById('flowDec');d.textContent=esc(c.decision);
  d.className='flow-dec '+(c.decision==='allow'?'badge-allow':c.decision==='deny'?'badge-deny':'badge-esc');
  document.getElementById('flowTime').textContent=esc(c.timestamp);
}
function clearFilters(){document.getElementById('fDec').value='';document.getElementById('fTool').value='';document.getElementById('fSrc').value='';document.getElementById('fDst').value='';loadConns();}
function startPoll(){stopPoll();let l=document.getElementById('liveMode');pollId=setInterval(()=>{if(l&&l.checked&&!document.getElementById('tab-connections').classList.contains('hidden'))loadConns();},3000);}
function stopPoll(){if(pollId){clearInterval(pollId);pollId=null;}}
function loadPolicy(){api('/api/policies').then(r=>r.json()).then(d=>{document.getElementById('policyEditor').value=d.content;});}
function validatePolicy(){api('/api/policies/validate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:document.getElementById('policyEditor').value})}).then(r=>r.json()).then(d=>alert(d.valid?'Valid':'Invalid: '+d.error));}
function savePolicy(){api('/api/policies',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:document.getElementById('policyEditor').value})}).then(r=>r.json()).then(d=>alert('Saved: '+JSON.stringify(d)));}
function reloadPolicy(){api('/api/policies/reload',{method:'POST'}).then(r=>r.json()).then(d=>alert('Reloaded: '+JSON.stringify(d)));}
function loadReceipts(){api('/api/receipts?limit=20').then(r=>r.json()).then(d=>{document.getElementById('receiptsView').textContent=JSON.stringify(d.receipts,null,2);});}
function loadSIEM(){api('/api/siem').then(r=>r.json()).then(d=>{document.getElementById('siemEnabled').checked=d.enabled;document.getElementById('siemBackend').value=d.backend||'';document.getElementById('siemUrl').value=d.url||'';});}
function saveSIEM(){api('/api/siem',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:document.getElementById('siemEnabled').checked,backend:document.getElementById('siemBackend').value,url:document.getElementById('siemUrl').value,token:document.getElementById('siemToken').value})}).then(r=>r.json()).then(d=>alert('Saved'));}
function loadUsers(){api('/api/users').then(r=>r.json()).then(d=>{let tb=document.querySelector('#userTable tbody');tb.innerHTML='';d.users.forEach(u=>tb.innerHTML+='<tr><td>'+esc(u.api_key)+'</td><td>'+esc(u.role)+'</td><td>'+esc(u.name)+'</td></tr>');});}
function addUser(){api('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({api_key:document.getElementById('newKey').value,role:document.getElementById('newRole').value,name:document.getElementById('newName').value})}).then(r=>r.json()).then(d=>{alert('Added');loadUsers();});}
function loadConfig(){api('/api/config').then(r=>r.json()).then(d=>{document.getElementById('configView').textContent=JSON.stringify(d,null,2);});}
setInterval(()=>{if(!document.getElementById('main').classList.contains('hidden')&&!document.getElementById('tab-dashboard').classList.contains('hidden'))loadStats();},5000);
</script>
</body>
</html>"""


__all__ = ["create_gateway_app", "create_admin_app"]
