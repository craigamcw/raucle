# provenance-go — Go reference implementation

A standard-library-only Go implementation of the
[Raucle Provenance Receipt v1 spec](https://raucle.com/spec/provenance/v1).

One of the cross-language reference implementations (Python, TypeScript,
Go, Rust). All four emit the same wire format and compute identical
content-addressed IDs — a receipt emitted by any verifies in the
others.

## Use

```go
import (
    "crypto/ed25519"
    prov "github.com/epic28-ltd/raucle/reference/provenance-go"
)

pub, priv, _ := ed25519.GenerateKey(nil)

r, err := prov.Emit(prov.Payload{
    Iss:              "https://acme.example/raucle",
    Iat:              time.Now().Unix(),
    AgentID:          "agent:acme.scanner",
    AgentKeyID:       "k_1",
    Operation:        "guardrail_scan",
    Parents:          []string{/* parent ids */},
    InputHash:        inputHashHex,
    OutputHash:       outputHashHex,
    Taint:            []string{"untrusted_user"},
    RulesetHash:      rulesetHashHex,
    GuardrailVerdict: "ALLOW",
}, priv)

parsed, err := prov.Verify(r.JWS, pub)
_ = r.ID // content-addressed identifier

// Multi-receipt graph:
chain, err := prov.BuildChain([]prov.Receipt{r1, r2, r3})
```

`BuildChain` enforces DAG closure, acyclicity, and taint monotonicity
(§7–§9); `Validate`/`Verify` enforce the envelope (§3) and payload
(§4) rules including the `crit=raucle/v1` JWT-confusion guard.

## Dependencies

None beyond the standard library (`crypto/ed25519`, `crypto/sha256`,
`encoding/*`).

## Develop

```bash
go vet ./...
go test ./...
```

`TestCanonicalParity` locks the canonical-JSON output to the exact
bytes the Python, TypeScript, and Rust encoders produce — that
byte-identity is what makes receipt IDs and signatures cross-language
compatible.

## License

MIT.
