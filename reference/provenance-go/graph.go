package provenance

import (
	"fmt"
	"sort"
	"strings"
)

// ChainError is returned when a chain violates the spec.
type ChainError struct{ msg string }

func (e *ChainError) Error() string { return e.msg }

func chainErr(format string, a ...any) *ChainError {
	return &ChainError{msg: fmt.Sprintf(format, a...)}
}

// Chain is a topologically-ordered, closed-under-parents list of
// receipts (§8).
type Chain struct {
	Receipts []Receipt
	ByID     map[string]Receipt
}

// BuildChain validates an ordered slice of already-verified receipts:
// DAG closure + acyclicity (§8) and taint monotonicity (§7). Mirrors the
// Python verifier: sanitisation may drop tags it lists in its `corpus`
// field as "removed:<comma-separated>".
func BuildChain(receipts []Receipt) (*Chain, error) {
	byID, err := buildByIDMap(receipts)
	if err != nil {
		return nil, err
	}
	for _, r := range receipts {
		if err := checkTaintMonotonicity(r, byID); err != nil {
			return nil, err
		}
	}
	return &Chain{Receipts: receipts, ByID: byID}, nil
}

func buildByIDMap(receipts []Receipt) (map[string]Receipt, error) {
	byID := make(map[string]Receipt, len(receipts))
	for _, r := range receipts {
		if _, dup := byID[r.ID]; dup {
			return nil, chainErr("duplicate receipt id in chain: %s", r.ID)
		}
		if err := checkParentClosure(r, byID); err != nil {
			return nil, err
		}
		byID[r.ID] = r
	}
	return byID, nil
}

func checkParentClosure(r Receipt, byID map[string]Receipt) error {
	for _, p := range r.Payload.Parents {
		if _, ok := byID[p]; !ok {
			return chainErr(
				"receipt %s references parent %s not earlier in the chain "+
					"(topo or closure violation)", r.ID, p)
		}
	}
	return nil
}

func collectParentTaint(r Receipt, byID map[string]Receipt) map[string]bool {
	parentTaint := map[string]bool{}
	for _, p := range r.Payload.Parents {
		for _, t := range byID[p].Payload.Taint {
			parentTaint[t] = true
		}
	}
	return parentTaint
}

func checkTaintMonotonicity(r Receipt, byID map[string]Receipt) error {
	if len(r.Payload.Parents) == 0 {
		return nil
	}
	parentTaint := collectParentTaint(r, byID)
	childTaint := map[string]bool{}
	for _, t := range r.Payload.Taint {
		childTaint[t] = true
	}
	if r.Payload.Operation == "sanitisation" {
		return checkSanitisationTaint(r, parentTaint, childTaint)
	}
	return checkNonSanitisationTaint(r, parentTaint, childTaint)
}

func checkSanitisationTaint(r Receipt, parentTaint, childTaint map[string]bool) error {
	removed := map[string]bool{}
	if strings.HasPrefix(r.Payload.Corpus, "removed:") {
		for _, s := range strings.Split(r.Payload.Corpus[len("removed:"):], ",") {
			if s != "" {
				removed[s] = true
			}
		}
	}
	var bad []string
	for t := range parentTaint {
		if !removed[t] && !childTaint[t] {
			bad = append(bad, t)
		}
	}
	for t := range childTaint {
		if !parentTaint[t] {
			bad = append(bad, "+"+t)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return chainErr(
			"sanitisation receipt %s taint mismatch vs corpus removed-set: %v",
			r.ID, bad)
	}
	return nil
}

func checkNonSanitisationTaint(r Receipt, parentTaint, childTaint map[string]bool) error {
	var missing []string
	for t := range parentTaint {
		if !childTaint[t] {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return chainErr(
			"taint monotonicity violation at %s: missing %v", r.ID, missing)
	}
	return nil
}
