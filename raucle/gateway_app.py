"""Admin panel + gateway API FastAPI application.

This module provides:
  - Gateway API on port 8080: POST /gate (agent tool calls)
  - Admin panel on port 8081: policy management, stats, receipts, config
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
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

    @app.post("/gate")
    def gate_tool_call(req: GateRequest) -> dict[str, Any]:
        """Gate a tool call. Returns allow/deny/escalate decision."""
        return gateway.check_tool_call(req.tool, req.args, req.agent_id)

    @app.get("/health")
    def health() -> dict[str, str]:
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

    # --- Health (no auth) ---
    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # --- Dashboard / Stats ---
    @app.get("/api/stats")
    def get_stats(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "stats")
        return gateway.get_stats()

    # --- Policy Management ---
    @app.get("/api/policies")
    def get_policies(authorization: str | None = Header(None)) -> dict[str, Any]:
        user = check_auth(authorization)
        check_access(user, "policies")
        policy_path = Path(gateway.config.policy_file)
        content = policy_path.read_text() if policy_path.exists() else ""
        return {"content": content, "path": str(policy_path)}

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
<title>Raucle Gateway Admin</title>
<style>
  :root { --bg: #0d1117; --fg: #e6edf3; --muted: #7d8590; --border: #30363d;
    --accent: #2f81f7; --green: #3fb950; --red: #f85149; --yellow: #d29922;
    --card: #161b22; --pad: 16px; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: var(--bg); color: var(--fg); }
  .header { background: var(--card); border-bottom: 1px solid var(--border);
    padding: 12px var(--pad); display: flex; align-items: center; gap: 12px; }
  .header h1 { font-size: 18px; font-weight: 600; }
  .header .badge { background: var(--accent); color: white; padding: 2px 8px;
    border-radius: 4px; font-size: 12px; }
  .tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); }
  .tab { padding: 10px 20px; cursor: pointer; color: var(--muted);
    border-bottom: 2px solid transparent; }
  .tab.active { color: var(--fg); border-bottom-color: var(--accent); }
  .content { padding: var(--pad); max-width: 1200px; margin: 0 auto; }
  .card { background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: var(--pad); margin-bottom: var(--pad); }
  .card h2 { font-size: 14px; color: var(--muted); margin-bottom: 12px; text-transform: uppercase; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: var(--pad); }
  .stat { text-align: center; }
  .stat .value { font-size: 32px; font-weight: 700; }
  .stat .label { font-size: 12px; color: var(--muted); margin-top: 4px; }
  .stat.allow .value { color: var(--green); }
  .stat.deny .value { color: var(--red); }
  .stat.escalate .value { color: var(--yellow); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 13px; }
  th { color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; }
  .editor { width: 100%; height: 400px; background: var(--bg); color: var(--fg);
    border: 1px solid var(--border); border-radius: 4px; padding: 12px;
    font-family: monospace; font-size: 13px; resize: vertical; }
  .btn { background: var(--accent); color: white; border: none; padding: 8px 16px;
    border-radius: 4px; cursor: pointer; font-size: 13px; }
  .btn:hover { opacity: 0.9; }
  .btn.danger { background: var(--red); }
  .actions { display: flex; gap: 8px; margin-top: 12px; }
  .login { max-width: 400px; margin: 80px auto; }
  .input { width: 100%; padding: 8px 12px; background: var(--bg); color: var(--fg);
    border: 1px solid var(--border); border-radius: 4px; font-size: 14px; margin-bottom: 12px; }
  .hidden { display: none; }
  pre { background: var(--bg); padding: 12px; border-radius: 4px;
    border: 1px solid var(--border); overflow-x: auto; font-size: 12px; }
</style>
</head>
<body>
<div class="header">
  <h1>Raucle Gateway</h1>
  <span class="badge">Admin</span>
</div>
<div id="login" class="content login">
  <div class="card">
    <h2>Authentication</h2>
    <input class="input" id="apiKey" type="password" placeholder="Admin API Key" />
    <button class="btn" onclick="login()">Login</button>
  </div>
</div>
<div id="main" class="hidden">
  <div class="tabs">
    <div class="tab active" onclick="showTab('dashboard')">Dashboard</div>
    <div class="tab" onclick="showTab('policies')">Policies</div>
    <div class="tab" onclick="showTab('receipts')">Receipts</div>
    <div class="tab" onclick="showTab('siem')">SIEM</div>
    <div class="tab" onclick="showTab('users')">Users</div>
    <div class="tab" onclick="showTab('config')">Config</div>
  </div>
  <div class="content">
    <div id="tab-dashboard">
      <div class="card"><h2>Gate Decisions</h2>
        <div class="stats-grid" id="statsGrid"></div>
      </div>
      <div class="card"><h2>By Tool</h2>
        <table id="toolTable"><thead><tr><th>Tool</th><th>Allow</th><th>Deny</th></tr></thead><tbody></tbody></table>
      </div>
    </div>
    <div id="tab-policies" class="hidden">
      <div class="card"><h2>Policy File</h2>
        <textarea class="editor" id="policyEditor"></textarea>
        <div class="actions">
          <button class="btn" onclick="validatePolicy()">Validate</button>
          <button class="btn" onclick="savePolicy()">Save & Deploy</button>
          <button class="btn" onclick="reloadPolicy()">Reload</button>
        </div>
      </div>
    </div>
    <div id="tab-receipts" class="hidden">
      <div class="card"><h2>Recent Receipts</h2>
        <pre id="receiptsView">Loading...</pre>
      </div>
    </div>
    <div id="tab-siem" class="hidden">
      <div class="card"><h2>SIEM Forwarding</h2>
        <label><input type="checkbox" id="siemEnabled"> Enabled</label><br><br>
        <input class="input" id="siemBackend" placeholder="splunk / elastic / sentinel">
        <input class="input" id="siemUrl" placeholder="SIEM endpoint URL">
        <input class="input" id="siemToken" type="password" placeholder="SIEM token">
        <button class="btn" onclick="saveSIEM()">Save</button>
      </div>
    </div>
    <div id="tab-users" class="hidden">
      <div class="card"><h2>Add User</h2>
        <input class="input" id="newKey" placeholder="API Key">
        <input class="input" id="newRole" placeholder="admin / operator / auditor">
        <input class="input" id="newName" placeholder="Name">
        <button class="btn" onclick="addUser()">Add</button>
      </div>
      <div class="card"><h2>Users</h2>
        <table id="userTable"><thead><tr><th>Key</th><th>Role</th><th>Name</th></tr></thead><tbody></tbody></table>
      </div>
    </div>
    <div id="tab-config" class="hidden">
      <div class="card"><h2>Configuration</h2><pre id="configView"></pre></div>
    </div>
  </div>
</div>
<script>
let key = '';
function login() {
  key = document.getElementById('apiKey').value;
  fetch('/api/stats', {headers: {'Authorization': key}})
    .then(r => { if (r.ok) { document.getElementById('login').classList.add('hidden');
      document.getElementById('main').classList.remove('hidden'); loadAll(); }
      else { alert('Invalid API key'); } });
}
function showTab(t) {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('[id^=tab-]').forEach(x => x.classList.add('hidden'));
  event.target.classList.add('active');
  document.getElementById('tab-' + t).classList.remove('hidden');
  if (t === 'dashboard') loadStats();
  if (t === 'policies') loadPolicy();
  if (t === 'receipts') loadReceipts();
  if (t === 'siem') loadSIEM();
  if (t === 'users') loadUsers();
  if (t === 'config') loadConfig();
}
function loadAll() { loadStats(); }
function api(path, opts) { return fetch(path, {...opts, headers: {'Authorization': key, ...((opts||{}).headers||{})}}); }
function loadStats() {
  api('/api/stats').then(r=>r.json()).then(d=>{
    document.getElementById('statsGrid').innerHTML =
      `<div class="stat"><div class="value">${d.total_requests}</div><div class="label">Total</div></div>` +
      `<div class="stat allow"><div class="value">${d.allowed}</div><div class="label">Allowed</div></div>` +
      `<div class="stat deny"><div class="value">${d.denied}</div><div class="label">Denied</div></div>` +
      `<div class="stat escalate"><div class="value">${d.escalated}</div><div class="label">Escalated</div></div>` +
      `<div class="stat"><div class="value">${d.avg_latency_us}</div><div class="label">Avg Latency (us)</div></div>`;
    let tb = document.querySelector('#toolTable tbody'); tb.innerHTML='';
    Object.entries(d.tools||{}).forEach(([t,s])=>tb.innerHTML+=`<tr><td>${t}</td><td>${s.allow||0}</td><td>${s.deny||0}</td></tr>`);
  });
}
function loadPolicy() { api('/api/policies').then(r=>r.json()).then(d=>{document.getElementById('policyEditor').value=d.content;}); }
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
function loadReceipts() { api('/api/receipts?limit=20').then(r=>r.json()).then(d=>{
  document.getElementById('receiptsView').textContent=JSON.stringify(d.receipts,null,2);}); }
function loadSIEM() { api('/api/siem').then(r=>r.json()).then(d=>{
  document.getElementById('siemEnabled').checked=d.enabled;
  document.getElementById('siemBackend').value=d.backend||'';
  document.getElementById('siemUrl').value=d.url||'';}); }
function saveSIEM() {
  api('/api/siem',{method:'PUT',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({enabled:document.getElementById('siemEnabled').checked,
      backend:document.getElementById('siemBackend').value,
      url:document.getElementById('siemUrl').value,
      token:document.getElementById('siemToken').value})}).then(r=>r.json()).then(d=>alert('Saved'));
}
function loadUsers() { api('/api/users').then(r=>r.json()).then(d=>{
  let tb=document.querySelector('#userTable tbody');tb.innerHTML='';
  d.users.forEach(u=>tb.innerHTML+=`<tr><td>${u.api_key}</td><td>${u.role}</td><td>${u.name||''}</td></tr>`);}); }
function addUser() {
  api('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({api_key:document.getElementById('newKey').value,
      role:document.getElementById('newRole').value,
      name:document.getElementById('newName').value})}).then(r=>r.json()).then(d=>{alert('Added');loadUsers();}); }
function loadConfig() { api('/api/config').then(r=>r.json()).then(d=>{
  document.getElementById('configView').textContent=JSON.stringify(d,null,2);}); }
setInterval(()=>{if(!document.getElementById('main').classList.contains('hidden'))loadStats();},5000);
</script>
</body>
</html>"""


__all__ = ["create_gateway_app", "create_admin_app"]
