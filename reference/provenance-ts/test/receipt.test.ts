import { test } from 'node:test'
import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { emit, verify, type ReceiptPayload } from '../src/receipt.js'
import { buildChain, ChainError } from '../src/graph.js'
import { canonicalString } from '../src/canonical.js'

const subtle = webcrypto.subtle
const here = dirname(fileURLToPath(import.meta.url))

async function genKey(): Promise<webcrypto.CryptoKeyPair> {
  return (await subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as unknown as webcrypto.CryptoKeyPair
}

function basePayload(over: Partial<ReceiptPayload> = {}): ReceiptPayload {
  return {
    iat: 1700000001,
    agent_id: 'agent:test.scanner',
    agent_key_id: 'k_test01',
    operation: 'user_input',
    parents: [],
    input_hash:
      'sha256:f8c3bf62a9aa3e6fc1619c250e48abe7519373d3edf41be62eb5dc45199af2ef',
    taint: ['untrusted_user'],
    ...over,
  }
}

// ── canonical ────────────────────────────────────────────────────

test('canonical sorts keys and rejects floats', () => {
  assert.equal(canonicalString({ b: 1, a: 2 }), '{"a":2,"b":1}')
  assert.throws(() => canonicalString(1.5), /integer/)
})

// ── emit/verify roundtrip ────────────────────────────────────────

test('emit/verify roundtrip preserves payload + stable id', async () => {
  const { privateKey, publicKey } = await genKey()
  const r = await emit(basePayload(), privateKey)
  const parsed = await verify(r.jws, publicKey)
  assert.equal(parsed.payload.agent_id, 'agent:test.scanner')
  assert.equal(parsed.id, r.id)
  assert.ok(r.id.startsWith('sha256:'))
  assert.equal(parsed.payload.iss, 'raucle-detect/provenance')
  assert.equal(parsed.payload.typ, 'provenance-receipt/v1')
})

test('verify rejects a different key', async () => {
  const a = await genKey()
  const b = await genKey()
  const r = await emit(basePayload(), a.privateKey)
  await assert.rejects(() => verify(r.jws, b.publicKey), /signature invalid/)
})

test('verify rejects wrong alg', async () => {
  const { privateKey, publicKey } = await genKey()
  const r = await emit(basePayload(), privateKey)
  const [, payloadB, sigB] = r.jws.split('.')
  const badHeader = Buffer.from(
    JSON.stringify({
      alg: 'HS256',
      typ: 'provenance-receipt/v1',
      kid: 'k_test01',
      crit: ['raucle/v1'],
      'raucle/v1': 'provenance',
    }),
  )
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '')
  await assert.rejects(
    () => verify(`${badHeader}.${payloadB}.${sigB}`, publicKey),
    /unsupported alg/,
  )
})

test('verify requires crit raucle/v1', async () => {
  const { privateKey, publicKey } = await genKey()
  const r = await emit(basePayload(), privateKey)
  const [, payloadB, sigB] = r.jws.split('.')
  const badHeader = Buffer.from(
    JSON.stringify({
      alg: 'EdDSA',
      typ: 'provenance-receipt/v1',
      kid: 'k_test01',
      crit: [],
      'raucle/v1': 'provenance',
    }),
  )
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '')
  await assert.rejects(
    () => verify(`${badHeader}.${payloadB}.${sigB}`, publicKey),
    /crit/,
  )
})

// ── payload validation ───────────────────────────────────────────

test('non-user_input requires parents', async () => {
  const { privateKey } = await genKey()
  const p = basePayload({ operation: 'model_call', parents: [], model: 'test-model-v1' })
  await assert.rejects(() => emit(p, privateKey), /parent/)
})

test('rejects reserved unknown field on emit', async () => {
  const { privateKey } = await genKey()
  const p = basePayload()
  ;(p as Record<string, unknown>)['rogue'] = true
  await assert.rejects(() => emit(p, privateKey), /reserved|unknown/)
})

test('allows x_ extension field', async () => {
  const { privateKey, publicKey } = await genKey()
  const p = basePayload()
  ;(p as Record<string, unknown>)['x_trace'] = 'abc'
  const r = await emit(p, privateKey)
  const parsed = await verify(r.jws, publicKey)
  assert.equal(parsed.payload['x_trace'], 'abc')
})

// ── chain DAG + taint ────────────────────────────────────────────

test('chain validates topo + closure', async () => {
  const { privateKey } = await genKey()
  const r1 = await emit(basePayload(), privateKey)
  const r2 = await emit(
    basePayload({
      operation: 'model_call',
      parents: [r1.id],
      taint: ['untrusted_user'],
      model: 'test-model-v1',
    }),
    privateKey,
  )
  const chain = buildChain([r1, r2])
  assert.deepEqual(chain.receipts.map((r) => r.id), [r1.id, r2.id])
})

test('chain rejects topo break', async () => {
  const { privateKey } = await genKey()
  const r1 = await emit(basePayload(), privateKey)
  const r2 = await emit(
    basePayload({
      operation: 'model_call',
      parents: [r1.id],
      taint: ['untrusted_user'],
      model: 'test-model-v1',
    }),
    privateKey,
  )
  assert.throws(() => buildChain([r2, r1]), ChainError)
})

test('chain rejects silent taint loss', async () => {
  const { privateKey } = await genKey()
  const r1 = await emit(basePayload(), privateKey)
  const r2 = await emit(
    basePayload({
      operation: 'model_call',
      parents: [r1.id],
      taint: [],
      model: 'test-model-v1',
    }),
    privateKey,
  )
  assert.throws(() => buildChain([r1, r2]), /monotonicity/)
})

test('sanitisation removes tag via corpus', async () => {
  const { privateKey } = await genKey()
  const r1 = await emit(basePayload(), privateKey)
  const ok = await emit(
    basePayload({
      operation: 'sanitisation',
      parents: [r1.id],
      taint: [],
      tool: 'redactor:pii-v1',
      corpus: 'removed:untrusted_user',
    }),
    privateKey,
  )
  const chain = buildChain([r1, ok])
  assert.equal(chain.receipts.length, 2)
})

test('sanitisation undeclared drop fails', async () => {
  const { privateKey } = await genKey()
  const r1 = await emit(basePayload(), privateKey)
  const bad = await emit(
    basePayload({
      operation: 'sanitisation',
      parents: [r1.id],
      taint: [],
      tool: 'redactor:pii-v1',
      corpus: 'removed:something_else',
    }),
    privateKey,
  )
  assert.throws(() => buildChain([r1, bad]), /corpus removed-set/)
})

// ── shared cross-language conformance: the published test vectors ──

function b64uToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  return new Uint8Array(Buffer.from(s.replaceAll('-', '+').replaceAll('_', '/') + pad, 'base64'))
}

async function importSeedKey(seedHex: string): Promise<webcrypto.CryptoKey> {
  const seed = Buffer.from(seedHex, 'hex')
  // PKCS#8 wrapper for a raw Ed25519 seed (RFC 8410).
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex')
  const pkcs8 = Buffer.concat([prefix, seed])
  return subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign'])
}

async function importPubPem(pem: string): Promise<webcrypto.CryptoKey> {
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s+/g, '')
  const der = new Uint8Array(Buffer.from(b64, 'base64'))
  return subtle.importKey('spki', der, { name: 'Ed25519' }, false, ['verify'])
}

test('spec vectors: verify + byte-identical re-emit', async () => {
  const vectorsPath = join(here, '..', '..', '..', 'docs', 'spec', 'provenance', 'v1', 'test-vectors.json')
  const vf = JSON.parse(readFileSync(vectorsPath, 'utf8'))
  const priv = await importSeedKey(vf.fixed_seed_hex)
  const pub = await importPubPem(vf.public_key_pem)

  assert.ok(vf.vectors.length > 0)
  for (const v of vf.vectors) {
    // (a) Verify the published JWS + recompute its content id.
    const r = await verify(v.expected_jws, pub)
    assert.equal(r.id, v.expected_receipt_hash, `${v.name}: receipt_hash mismatch`)

    // (b) Re-emit from the fixed seed; the TS JWS + id MUST be
    //     byte-identical to the published vector.
    const payloadObj = JSON.parse(
      new TextDecoder().decode(b64uToBytes(v.expected_jws.split('.')[1])),
    ) as ReceiptPayload
    const emitted = await emit(payloadObj, priv)
    assert.equal(emitted.jws, v.expected_jws, `${v.name}: emitted JWS differs`)
    assert.equal(emitted.id, v.expected_receipt_hash, `${v.name}: emitted id differs`)
  }
})

// Live bug #2 (§8.10): a correctly-signed JWS whose payload bytes are valid
// JSON but not JCS-canonical (here pretty-printed) must be rejected — otherwise
// byte-different receipts for the same logical content would verify.
test('verify rejects non-canonical payload bytes', async () => {
  const { privateKey, publicKey } = await genKey()
  const r = await emit(basePayload(), privateKey)
  const [headerB, payloadB] = r.jws.split('.')
  const b64u = (b: Uint8Array) =>
    Buffer.from(b).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
  const b64uDecode = (s: string) =>
    new Uint8Array(Buffer.from(s.replaceAll('-', '+').replaceAll('_', '/'), 'base64'))
  const obj = JSON.parse(new TextDecoder().decode(b64uDecode(payloadB)))
  const noncanon = new TextEncoder().encode(JSON.stringify(obj, null, 2)) // whitespace
  const signingInput = `${headerB}.${b64u(noncanon)}`
  const sig = new Uint8Array(
    await subtle.sign('Ed25519', privateKey, new TextEncoder().encode(signingInput)),
  )
  await assert.rejects(() => verify(`${signingInput}.${b64u(sig)}`, publicKey), /canonical/)
})
