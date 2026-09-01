// Command emit is a conformance-harness helper: it reads JSON requests
// {"seed_hex": "...", "payload": {...}} (one per line) from stdin and
// writes {"jws": "...", "id": "..."} (one per line) to stdout, using the
// Go reference implementation. See reference/conformance.py.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	provenance "github.com/epic28-ltd/raucle/reference/provenance-go"
)

type req struct {
	SeedHex string         `json:"seed_hex"`
	Payload map[string]any `json:"payload"`
}

func newScanner() *bufio.Scanner {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	return sc
}

func fail(stage string, err error) {
	fmt.Fprintln(os.Stderr, stage+":", err)
	os.Exit(1)
}

// runCanon reads {"obj": <value>} lines and writes {"hex": "<utf8 hex of
// canonical bytes>"}. JSON numbers unmarshal to float64; canonicalWrite accepts
// integral float64 in the safe range and rejects non-integers / out-of-range
// values (exit non-zero), which is what the invalid-vector checks rely on.
func runCanon(sc *bufio.Scanner, out *bufio.Writer) {
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if err := provenance.RejectLoneSurrogatesRaw(line); err != nil {
			fail("decode", err)
		}
		var cr struct {
			Obj any `json:"obj"`
		}
		if err := json.Unmarshal(line, &cr); err != nil {
			fail("decode", err)
		}
		b, err := provenance.CanonicalEncode(cr.Obj)
		if err != nil {
			fail("canon", err)
		}
		o, _ := json.Marshal(map[string]string{"hex": hex.EncodeToString(b)})
		out.Write(o)
		out.WriteByte('\n')
	}
}

// runEmit reads {"seed_hex","payload"} lines and writes {"jws","id"}.
func runEmit(sc *bufio.Scanner, out *bufio.Writer) {
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		// Reject lone surrogates on the RAW request before Unmarshal: encoding/json
		// silently substitutes U+FFFD, which would let Go sign a payload that
		// Python/TS reject — the same cross-language divergence guarded in runCanon,
		// but on the path that actually produces signed receipts.
		if err := provenance.RejectLoneSurrogatesRaw(line); err != nil {
			fail("decode", err)
		}
		var r req
		if err := json.Unmarshal(line, &r); err != nil {
			fail("decode", err)
		}
		seed, _ := hex.DecodeString(r.SeedHex)
		priv := ed25519.NewKeyFromSeed(seed)
		p := provenance.PayloadFromHarness(r.Payload)
		rec, err := provenance.Emit(p, priv)
		if err != nil {
			fail("emit", err)
		}
		b, _ := json.Marshal(map[string]string{"jws": rec.JWS, "id": rec.ID})
		out.Write(b)
		out.WriteByte('\n')
	}
}

func main() {
	sc := newScanner()
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	if len(os.Args) > 1 && os.Args[1] == "--canon" {
		runCanon(sc, out)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--verify" {
		runVerify(sc, out)
		return
	}
	runEmit(sc, out)
}

// runVerify reads {"jws","public_key_hex"} lines (the raw 32-byte Ed25519 public
// key, hex-encoded) and writes a verdict per line:
// {"verdict":"ACCEPT","id":"sha256:..."} or {"verdict":"REJECT"}. ANY error
// (bad key, bad signature, non-canonical bytes, duplicate key, malformed JWS) is
// a REJECT — the conformance harness asserts valid receipts ACCEPT and the
// invalid_receipt_vectors REJECT across every port.
func runVerify(sc *bufio.Scanner, out *bufio.Writer) {
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var vr struct {
			JWS    string `json:"jws"`
			PubHex string `json:"public_key_hex"`
		}
		if err := json.Unmarshal(line, &vr); err != nil {
			fail("decode", err)
		}
		verdict := map[string]string{"verdict": "REJECT"}
		if raw, herr := hex.DecodeString(vr.PubHex); herr == nil && len(raw) == ed25519.PublicKeySize {
			if rec, verr := provenance.Verify(vr.JWS, ed25519.PublicKey(raw)); verr == nil {
				verdict = map[string]string{"verdict": "ACCEPT", "id": rec.ID}
			}
		}
		b, _ := json.Marshal(verdict)
		out.Write(b)
		out.WriteByte('\n')
	}
}
