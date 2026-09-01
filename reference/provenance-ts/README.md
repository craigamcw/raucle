# @raucle/provenance — TypeScript reference implementation

A faithful, zero-dependency TypeScript implementation of the
[Raucle Provenance Receipt v1 spec](https://raucle.com/spec/provenance/v1).

This is one of the cross-language reference implementations (alongside
the Python implementation in [`raucle`](https://github.com/epic28-ltd/raucle)).
It emits and verifies the same wire format and computes the same
content-addressed identifiers — a receipt emitted by the Python
library verifies here, and vice versa.

## Install

```bash
npm install @raucle/provenance
```

Requires Node ≥ 20 (uses the built-in `webcrypto` Ed25519 + SHA-256;
no native or third-party crypto dependency).

## Use

```ts
import { webcrypto } from 'node:crypto'
import { emit, verify, buildChain } from '@raucle/provenance'

const { privateKey, publicKey } = (await webcrypto.subtle.generateKey(
  { name: 'Ed25519' },
  true,
  ['sign', 'verify'],
)) as webcrypto.CryptoKeyPair

const receipt = await emit(
  {
    iss: 'https://acme.example/raucle',
    iat: Math.floor(Date.now() / 1000),
    agent_id: 'agent:acme.scanner',
    agent_key_id: 'k_1',
    operation: 'guardrail_scan',
    parents: [/* parent receipt ids */],
    input_hash: '…64-hex-sha256…',
    output_hash: '…64-hex-sha256…',
    taint: ['untrusted_user'],
    ruleset_hash: '…64-hex-sha256…',
    guardrail_verdict: 'ALLOW',
  },
  privateKey,
)

console.log(receipt.id) // content-addressed identifier
const parsed = await verify(receipt.jws, publicKey)
```

For multi-receipt graphs, verify each receipt with `verify()` then
pass the topologically-ordered list to `buildChain()`, which enforces
DAG closure, acyclicity, and taint monotonicity (§7–§9):

```ts
const chain = buildChain([r1, r2, r3]) // throws ChainError on violation
```

## What it enforces

* **Envelope (§3):** EdDSA, `typ=provenance-receipt/v1`,
  `crit=["raucle/v1"]`, `kid === payload.agent_key_id`. The `crit`
  header is the JWT-confusion guard — generic JWT libraries reject it.
* **Payload (§4):** sorted taint, hash formats, operation-specific
  required descriptors, `x_`-prefixed extensions only.
* **Content addressing (§8):** id = hex SHA-256 of the Compact JWS
  ASCII bytes. Deterministic and cross-language stable.
* **Taint monotonicity (§7):** descendant taint ⊇ ∪(parent taint),
  except an explicit `sanitisation` receipt that declares removed tags
  in `x_removed_taint`.

## Cross-language parity

The canonical-JSON encoder (`src/canonical.ts`) produces byte-identical
output to the Python implementation's encoder, which is what guarantees
the same signed bytes and the same receipt IDs across languages. This
is checked manually in CI; if you change the encoder, re-verify against
the Python impl.

## Develop

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # node --test over test/**/*.test.ts
npm run build       # emit dist/
```

## License

MIT.
