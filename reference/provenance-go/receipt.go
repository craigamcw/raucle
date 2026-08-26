package provenance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// This implementation mirrors the canonical Python reference
// (raucle/provenance.py) byte-for-byte: same JOSE header (incl.
// the "raucle/v1": "provenance" tag), same payload field set/ordering,
// same string-typed model/tool/corpus, sha256:-prefixed hashes, and the
// same content-addressed id ("sha256:" + hex(sha256(jws))).

const (
	iss       = "raucle-detect/provenance"
	typ       = "provenance-receipt/v1"
	jwsTyp    = typ
	critLabel = "raucle/v1"
)

var validOperations = map[string]bool{
	"user_input": true, "model_call": true, "tool_call": true,
	"retrieval": true, "guardrail_scan": true, "agent_handoff": true,
	"sanitisation": true, "merge": true,
}

var jwsCrit = []string{critLabel}

// knownFields is the closed set of payload keys a verifier accepts
// (plus x_-prefixed extensions). Mirrors the spec §4 field list.
var knownFields = map[string]bool{
	"iss": true, "typ": true, "iat": true, "agent_id": true,
	"agent_key_id": true, "operation": true, "parents": true,
	"input_hash": true, "output_hash": true, "taint": true,
	"ruleset_hash": true, "guardrail_verdict": true, "model": true,
	"tool": true, "corpus": true, "tenant": true,
}

// Payload is the v1 receipt payload (§4). String-typed hash/model/tool
// fields mirror the canonical Python reference exactly.
type Payload struct {
	Iat              int64
	AgentID          string
	AgentKeyID       string
	Operation        string
	Parents          []string
	Taint            []string
	InputHash        string // empty means absent; value is "sha256:<hex>"
	OutputHash       string // empty means absent
	Model            string // empty means absent
	Tool             string // empty means absent
	Corpus           string // empty means absent
	RulesetHash      string // empty means absent
	GuardrailVerdict string // empty means absent
	Tenant           string // empty means absent; "" tenant set via TenantSet
	TenantSet        bool   // mirrors Python's `tenant is not None`
}

// Receipt is a signed payload.
type Receipt struct {
	JWS     string
	Payload Payload
	// ID is the content-addressed identifier (§8): "sha256:" + hex
	// SHA-256 of the Compact JWS ASCII bytes.
	ID string
}

func b64u(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64uDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func sha256Hex(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

// Validate enforces the §4 payload rules. It is intentionally lenient in
// the same places the Python reference is: it does not re-shape hashes
// or models, it only enforces structural invariants the spec mandates.
func (p *Payload) Validate() error {
	if !validOperations[p.Operation] {
		return fmt.Errorf("unknown operation: %s", p.Operation)
	}
	if err := validateOperationFields(p); err != nil {
		return err
	}
	if err := validateParentRules(p); err != nil {
		return err
	}
	return validateSortedUnique(p)
}

func validateOperationFields(p *Payload) error {
	if p.Operation == "guardrail_scan" && p.GuardrailVerdict == "" {
		return fmt.Errorf("guardrail_scan requires a verdict (§4)")
	}
	if p.Operation == "guardrail_scan" && p.RulesetHash == "" {
		return fmt.Errorf("guardrail_scan requires ruleset_hash (§4)")
	}
	if p.Operation == "model_call" && p.Model == "" {
		return fmt.Errorf("model_call requires model (§4)")
	}
	if (p.Operation == "tool_call" || p.Operation == "sanitisation") && p.Tool == "" {
		return fmt.Errorf("%s requires tool (§4)", p.Operation)
	}
	if (p.Operation == "retrieval" || p.Operation == "sanitisation") && p.Corpus == "" {
		return fmt.Errorf("%s requires corpus (§4)", p.Operation)
	}
	return nil
}

func validateParentRules(p *Payload) error {
	if p.Operation == "user_input" && len(p.Parents) > 0 {
		return fmt.Errorf("user_input must have no parents")
	}
	if p.Operation != "user_input" && len(p.Parents) == 0 {
		return fmt.Errorf("%s requires at least one parent", p.Operation)
	}
	return nil
}

// §4.2/§4.3.1: parents and taint MUST be sorted in UTF-16 code-unit order
// and unique. A strictly-increasing check enforces both at once (a non-
// conformant emitter could otherwise sign an unsorted/duplicated array).
func validateSortedUnique(p *Payload) error {
	for _, f := range []struct {
		name string
		vals []string
	}{{"parents", p.Parents}, {"taint", p.Taint}} {
		for i := 1; i < len(f.vals); i++ {
			if !lessUTF16(f.vals[i-1], f.vals[i]) {
				return fmt.Errorf("%s must be sorted in UTF-16 code-unit order and unique (§4.3.1)", f.name)
			}
		}
	}
	return nil
}

// toMap builds the canonical payload object exactly as Python's
// ProvenanceReceipt.payload() does. Parents and taint are sorted.
func (p *Payload) toMap() map[string]any {
	parentsAny := sortedAnySlice(p.Parents)
	taintAny := sortedAnySlice(p.Taint)

	m := map[string]any{
		"iss":          iss,
		"typ":          typ,
		"iat":          p.Iat,
		"agent_id":     p.AgentID,
		"agent_key_id": p.AgentKeyID,
		"operation":    p.Operation,
		"parents":      parentsAny,
		"taint":        taintAny,
	}
	setOptional(m, "input_hash", p.InputHash)
	setOptional(m, "output_hash", p.OutputHash)
	setOptional(m, "model", p.Model)
	setOptional(m, "tool", p.Tool)
	setOptional(m, "corpus", p.Corpus)
	setOptional(m, "ruleset_hash", p.RulesetHash)
	setOptional(m, "guardrail_verdict", p.GuardrailVerdict)
	if p.TenantSet {
		m["tenant"] = p.Tenant
	}
	return m
}

func sortedAnySlice(ss []string) []any {
	sorted := append([]string(nil), ss...)
	sort.Slice(sorted, func(i, j int) bool { return lessUTF16(sorted[i], sorted[j]) })
	out := make([]any, len(sorted))
	for i, v := range sorted {
		out[i] = v
	}
	return out
}

func setOptional(m map[string]any, key, value string) {
	if value != "" {
		m[key] = value
	}
}

func payloadFromMap(m map[string]any) (Payload, error) {
	for k := range m {
		if !knownFields[k] && (len(k) < 2 || k[:2] != "x_") {
			return Payload{}, fmt.Errorf("reserved unknown field: %s", k)
		}
	}
	// typ must equal the spec literal (§4).
	if t, _ := m["typ"].(string); t != typ {
		return Payload{}, fmt.Errorf("payload typ must be %q, got %q", typ, t)
	}
	p := Payload{}
	getStr := func(k string) string {
		if v, ok := m[k].(string); ok {
			return v
		}
		return ""
	}
	if iat, ok := m["iat"].(float64); ok {
		p.Iat = int64(iat)
	}
	p.AgentID = getStr("agent_id")
	p.AgentKeyID = getStr("agent_key_id")
	p.Operation = getStr("operation")
	p.InputHash = getStr("input_hash")
	p.OutputHash = getStr("output_hash")
	p.Model = getStr("model")
	p.Tool = getStr("tool")
	p.Corpus = getStr("corpus")
	p.RulesetHash = getStr("ruleset_hash")
	p.GuardrailVerdict = getStr("guardrail_verdict")
	if tv, ok := m["tenant"]; ok {
		p.TenantSet = true
		if s, ok := tv.(string); ok {
			p.Tenant = s
		}
	}
	p.Parents = stringSliceFromAny(m["parents"])
	p.Taint = stringSliceFromAny(m["taint"])
	return p, nil
}

func stringSliceFromAny(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// PayloadFromHarness builds a Payload from a decoded JSON object as used
// by the cross-language conformance harness. It tolerates payloads that
// already carry the constant iss/typ (they are re-injected on emit).
func PayloadFromHarness(m map[string]any) Payload {
	p, _ := payloadFromMap(m)
	return p
}

// Emit signs a payload and returns a Receipt.
func Emit(p Payload, priv ed25519.PrivateKey) (Receipt, error) {
	if err := p.Validate(); err != nil {
		return Receipt{}, err
	}
	header := map[string]any{
		"alg":       "EdDSA",
		"typ":       jwsTyp,
		"kid":       p.AgentKeyID,
		"crit":      toAnySlice(jwsCrit),
		critLabel:   "provenance",
	}
	headerB, err := canonicalEncode(header)
	if err != nil {
		return Receipt{}, err
	}
	payloadB, err := canonicalEncode(p.toMap())
	if err != nil {
		return Receipt{}, err
	}
	signingInput := b64u(headerB) + "." + b64u(payloadB)
	sig := ed25519.Sign(priv, []byte(signingInput))
	jws := signingInput + "." + b64u(sig)
	return Receipt{JWS: jws, Payload: p, ID: "sha256:" + sha256Hex([]byte(jws))}, nil
}

// Verify checks a Compact JWS against pub and parses it.
func Verify(jws string, pub ed25519.PublicKey) (Receipt, error) {
	parts := splitN(jws, '.')
	if len(parts) != 3 {
		return Receipt{}, fmt.Errorf("JWS must have three segments")
	}
	headerB, payloadB, sigB := parts[0], parts[1], parts[2]

	hb, err := b64uDecode(headerB)
	if err != nil {
		return Receipt{}, err
	}
	var header map[string]any
	if err := json.Unmarshal(hb, &header); err != nil {
		return Receipt{}, err
	}
	if err := validateHeader(header, hb); err != nil {
		return Receipt{}, err
	}

	sig, err := b64uDecode(sigB)
	if err != nil {
		return Receipt{}, err
	}
	if !ed25519.Verify(pub, []byte(headerB+"."+payloadB), sig) {
		return Receipt{}, fmt.Errorf("signature invalid")
	}

	p, err := decodePayload(payloadB)
	if err != nil {
		return Receipt{}, err
	}
	if header["kid"] != p.AgentKeyID {
		return Receipt{}, fmt.Errorf("header.kid != payload.agent_key_id (§3)")
	}
	return Receipt{JWS: jws, Payload: p, ID: "sha256:" + sha256Hex([]byte(jws))}, nil
}

func validateHeader(header map[string]any, hb []byte) error {
	if header["alg"] != "EdDSA" {
		return fmt.Errorf("unsupported alg: %v", header["alg"])
	}
	if header["typ"] != jwsTyp {
		return fmt.Errorf("unexpected typ: %v", header["typ"])
	}
	crit, ok := header["crit"].([]any)
	if !ok || len(crit) != 1 || crit[0] != critLabel {
		return fmt.Errorf("crit must be exactly ['raucle/v1']")
	}
	if header[critLabel] != "provenance" {
		return fmt.Errorf("header 'raucle/v1' must be 'provenance'")
	}
	allowedHeaderKeys := map[string]bool{"alg": true, "typ": true, "kid": true, "crit": true, critLabel: true}
	for k := range header {
		if !allowedHeaderKeys[k] {
			return fmt.Errorf("unexpected JOSE header key: %s", k)
		}
	}
	// Canonical byte-equality (spec v1 §4.3, matches the Python reference): the
	// signature binds the on-wire bytes, but without re-encoding and comparing,
	// a non-canonical header (unsorted keys / extra whitespace) would still
	// verify, admitting byte-different receipts for the same logical content.
	if canonHeader, cerr := canonicalEncode(header); cerr != nil {
		return cerr
	} else if !bytes.Equal(canonHeader, hb) {
		return fmt.Errorf("JOSE header is not canonical JSON (JCS)")
	}
	return nil
}

func decodePayload(payloadB string) (Payload, error) {
	pb, err := b64uDecode(payloadB)
	if err != nil {
		return Payload{}, err
	}
	var pm map[string]any
	if err := json.Unmarshal(pb, &pm); err != nil {
		return Payload{}, err
	}
	if canonPayload, cerr := canonicalEncode(pm); cerr != nil {
		return Payload{}, cerr
	} else if !bytes.Equal(canonPayload, pb) {
		return Payload{}, fmt.Errorf("JWS payload is not canonical JSON (JCS)")
	}
	p, err := payloadFromMap(pm)
	if err != nil {
		return Payload{}, err
	}
	if err := p.Validate(); err != nil {
		return Payload{}, err
	}
	return p, nil
}

// ── small helpers ─────────────────────────────────────────────────

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func containsAny(xs []any, want string) bool {
	for _, x := range xs {
		if s, ok := x.(string); ok && s == want {
			return true
		}
	}
	return false
}

func splitN(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// equalStringSets is used by the chain verifier.
func equalStringSlices(a, b []string) bool {
	return reflect.DeepEqual(a, b)
}
