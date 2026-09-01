// raucle sidecar — Bicep template for Azure AI Foundry MCP gateway integration.
//
// Provisions a Container App running the raucle HTTP server inside
// the same VNet as the customer's Foundry-attached APIM instance, plus
// an APIM Backend pool member pointing at it. Run via:
//
//   az deployment group create \
//     -g <resource-group> \
//     -f deploy/foundry-mcp-sidecar/bicep/main.bicep \
//     -p @deploy/foundry-mcp-sidecar/bicep/parameters.example.json
//
// Companion docs:
//   - deploy/foundry-mcp-sidecar/README.md   (customer walkthrough)
//   - deploy/foundry-mcp-sidecar/apim-policy.xml
//   - docs/proposals/foundry-mcp-gateway.md  (design rationale)

@description('Azure region for the sidecar resources. Should match the region of the existing APIM instance.')
param location string = resourceGroup().location

@description('Container App Environment resource ID (existing). The sidecar deploys into this environment so it shares the APIM VNet.')
param containerAppEnvironmentId string

@description('Existing APIM service name (Foundry-attached).')
param apimServiceName string

@description('URL of the customer\'s existing MCP server. The sidecar forwards admitted calls here.')
param mcpBackendUrl string

@description('Existing Key Vault resource ID holding the raucle issuer Ed25519 private key.')
param keyVaultId string

@description('Key Vault secret name for the issuer private key PEM.')
param issuerKeySecretName string = 'raucle-issuer-private-key'

@description('Existing Storage Account resource ID for the audit log container.')
param auditStorageAccountId string

@description('Blob container name for the hash-chained audit log.')
param auditContainerName string = 'raucle-audit'

@description('raucle container image. Defaults to the latest GA tag on GHCR.')
param raucleImage string = 'ghcr.io/epic28-ltd/raucle:v0.12.0'

@description('Issuer string (e.g. "acme.bank.kyc-platform"). Embedded in every emitted receipt.')
param issuerId string

@description('Base URL the deploying organisation publishes its issuer pubkey + policy registry at. Used by external verifiers.')
param verificationBaseUrl string

// ---------------------------------------------------------------------------
// User-assigned managed identity — used by the sidecar to read the Key
// Vault secret and write to the audit storage container.

resource sidecarIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: 'raucle-sidecar-identity'
  location: location
}

// Grant the identity Key Vault secret-read access (for the issuer key)
// and Storage Blob Data Contributor on the audit container.
resource kvAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVaultId, sidecarIdentity.id, 'kv-secrets-user')
  scope: resourceGroup()  // refined to the KV scope by the customer if needed
  properties: {
    // "Key Vault Secrets User" role definition id (Azure built-in)
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '4633458b-17de-408a-b874-0445c86b69e6'
    )
    principalId: sidecarIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource blobAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(auditStorageAccountId, sidecarIdentity.id, 'blob-contributor')
  scope: resourceGroup()
  properties: {
    // "Storage Blob Data Contributor" role definition id
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
    )
    principalId: sidecarIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// The sidecar Container App itself.

resource sidecar 'Microsoft.App/containerApps@2025-01-01' = {
  name: 'raucle-sidecar'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${sidecarIdentity.id}': {}
    }
  }
  properties: {
    environmentId: containerAppEnvironmentId
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: false   // VNet-internal — APIM is the only entry point.
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
      }
      secrets: [
        // Key Vault reference; resolved at runtime via the managed identity.
        {
          name: 'issuer-key-pem'
          keyVaultUrl: '${reference(keyVaultId, '2024-11-01').vaultUri}secrets/${issuerKeySecretName}'
          identity: sidecarIdentity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'raucle'
          image: raucleImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          command: [
            'raucle'
            'serve'
            '--port'
            '8080'
            '--mode'
            'foundry-sidecar'
          ]
          env: [
            { name: 'RAUCLE_BACKEND_URL', value: mcpBackendUrl }
            { name: 'RAUCLE_ISSUER_ID', value: issuerId }
            { name: 'RAUCLE_ISSUER_KEY_PEM', secretRef: 'issuer-key-pem' }
            { name: 'RAUCLE_AUDIT_BLOB_ACCOUNT', value: split(auditStorageAccountId, '/')[8] }
            { name: 'RAUCLE_AUDIT_BLOB_CONTAINER', value: auditContainerName }
            { name: 'RAUCLE_VERIFICATION_BASE_URL', value: verificationBaseUrl }
            { name: 'AZURE_CLIENT_ID', value: sidecarIdentity.properties.clientId }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: { path: '/healthz', port: 8080 }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: { path: '/readyz', port: 8080 }
              initialDelaySeconds: 3
              periodSeconds: 5
            }
          ]
        }
      ]
      scale: {
        minReplicas: 2  // keep one warm for sub-100µs gate latency target
        maxReplicas: 20
        rules: [
          {
            name: 'http-scale'
            http: { metadata: { concurrentRequests: '50' } }
          }
        ]
      }
    }
  }
}

// ---------------------------------------------------------------------------
// APIM Backend pool member pointing at the sidecar's internal FQDN.

resource apimBackend 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  name: '${apimServiceName}/raucle-sidecar'
  properties: {
    description: 'raucle sidecar — gates every Foundry MCP tool call'
    url: 'https://${sidecar.properties.configuration.ingress.fqdn}'
    protocol: 'http'
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
  }
}

// ---------------------------------------------------------------------------
// APIM Named Values that the policy XML expects.

resource nvSidecarFqdn 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = {
  name: '${apimServiceName}/raucle-sidecar-fqdn'
  properties: {
    displayName: 'raucle-sidecar-fqdn'
    value: sidecar.properties.configuration.ingress.fqdn
    secret: false
  }
}

resource nvMcpPath 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = {
  name: '${apimServiceName}/raucle-mcp-path'
  properties: {
    displayName: 'raucle-mcp-path'
    value: '/mcp'
    secret: false
  }
}

// ---------------------------------------------------------------------------
// Outputs

output sidecarFqdn string = sidecar.properties.configuration.ingress.fqdn
output sidecarIdentityClientId string = sidecarIdentity.properties.clientId
output apimBackendId string = apimBackend.id
