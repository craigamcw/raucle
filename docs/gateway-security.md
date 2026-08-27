# Raucle Gateway - Production Security Guide

## TLS Termination

The gateway runs on plain HTTP. Production deployments MUST use a reverse
proxy with TLS termination. The included `docker-compose.gateway.yml`
uses Caddy with automatic Let's Encrypt certificates.

```bash
# Set your domain and admin key
export RAUCLE_DOMAIN=raucle.example.com
export RAUCLE_ADMIN_KEY=your-secure-key

# Deploy with TLS
docker compose -f docker-compose.gateway.yml up -d
```

The gateway container is NOT exposed to the host directly. All traffic
goes through Caddy on port 443. The internal Docker network
(`raucle-internal`) isolates the gateway from direct external access.

## WAF (Web Application Firewall)

For additional protection on the admin panel, deploy ModSecurity with
the OWASP Core Rule Set in front of Caddy:

```nginx
# nginx + ModSecurity alternative to Caddy
modsecurity on;
modsecurity_rules_file /etc/modsecurity/owasp-crs.conf;

location / {
    proxy_pass http://raucle-gateway:8081;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

## Rate Limiting

The gateway includes built-in rate limiting via `slowapi` (200 requests
per minute on `/gate`, 1000/min default). Caddy also provides per-IP
rate limiting at the proxy layer (100 requests/minute).

## API Key Management

- API keys are required for all admin panel endpoints
- Keys use constant-time comparison (`hmac.compare_digest`)
- Keys can have expiry timestamps for rotation
- The default admin key is created from `RAUCLE_ADMIN_KEY` at startup
- Additional users can be created via the admin panel with role-based
  access control (admin, operator, auditor)

## Health Check Authentication

Set `RAUCLE_HEALTH_KEY` to require authentication on `/health` endpoints.
This prevents unauthenticated health probes from revealing service status.
The Docker healthcheck uses the internal container network, so it works
even with health check auth enabled.

## Docker Security

- Container runs as non-root `raucle` user
- No default admin key in the image (must be injected at runtime)
- Internal Docker network isolates the gateway
- Data volume (`raucle-data`) persists receipts and audit logs
- Policy files mounted read-only

## Secrets Management

For production, use Docker secrets or a secrets manager instead of
environment variables for sensitive values:

```yaml
# docker-compose.secrets.yml
services:
  raucle-gateway:
    secrets:
      - admin_key
      - kms_key
secrets:
  admin_key:
    file: ./secrets/admin_key.txt
  kms_key:
    file: ./secrets/kms_key.txt
```

Then in the gateway:
```bash
RAUCLE_ADMIN_KEY_FILE=/run/secrets/admin_key
```

## SIEM Integration

Gate decisions are forwarded to SIEM in real-time. Supported backends:
- Splunk HEC
- Elasticsearch
- Azure Sentinel (Log Analytics)

Failed SIEM forwards are buffered in memory and retried.