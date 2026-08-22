/**
 * Canonical-JSON encoder (RFC 8785 JCS, minimal subset).
 *
 * The bytes produced here are the bytes that get signed and hashed, so
 * any drift between this and the other reference implementations
 * (Python, Go, Rust) is a spec-conformance bug. Keep it boring:
 * sorted keys, no insignificant whitespace, UTF-8. Floats are rejected
 * — the v1 payload schema doesn't use them, and float canonicalisation
 * is the one genuinely hard part of JCS.
 */

/**
 * Sort strings by UTF-16 code unit — the ordering RFC 8785 (JCS) mandates for
 * object keys, and the ordering JavaScript's default `Array.prototype.sort()`
 * already uses for strings. Provided EXPLICITLY (rather than a bare `.sort()`)
 * so the cross-language byte-identity contract is visible and lint-clean.
 *
 * DO NOT replace with `localeCompare`: it is locale-aware, does not match
 * code-unit ordering, and would silently break byte-identity with the Python /
 * Go / Rust / C# reference implementations.
 */
export function byCodeUnit(a: string, b: string): number {
  if (a < b) return -1
  if (a > b) return 1
  return 0
}

/**
 * Reject unpaired UTF-16 surrogates. JS strings are UTF-16, so a valid non-BMP
 * character is a high+low surrogate PAIR; a high surrogate not followed by a low
 * (or a low not preceded by a high) is a lone surrogate. `JSON.stringify` would
 * emit such a code unit as a `\udXXX` escape, whereas Python and Rust reject it
 * and Go/.NET substitute U+FFFD — a silent cross-implementation byte divergence.
 * Rejecting here is the only portable contract (§4.3.4).
 */
function rejectLoneSurrogates(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.codePointAt(i)!
    // codePointAt returns the full code point for a valid surrogate pair,
    // so a value > 0xFFFF means a valid pair — skip both code units.
    if (c > 0xFFFF) {
      i++ // valid surrogate pair — skip the low surrogate
      continue
    }
    // Values in the surrogate range (0xD800–0xDFFF) here are lone surrogates
    // (codePointAt on a lone surrogate returns the surrogate code unit itself).
    if (c >= 0xd800 && c <= 0xdfff) {
      throw new TypeError(
        `canonical-JSON: lone surrogate U+${c.toString(16).toUpperCase().padStart(4, '0')} ` +
          'is not permitted in v1 signed/hashed material',
      )
    }
  }
}

export function canonicalEncode(value: unknown): Uint8Array {
  check(value)
  return new TextEncoder().encode(canonicalString(value))
}

export function canonicalString(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    // Number.isSafeInteger (not isInteger): rejects non-integers AND integers
    // outside ±(2^53-1), which are lossy as IEEE-754 doubles and would not
    // round-trip byte-identically against the Go/Rust/C# 64-bit ports (§8.10 #6).
    if (!Number.isSafeInteger(value)) {
      throw new TypeError(
        'canonical-JSON: only safe integers (|n| <= 2^53-1) are supported in v1',
      )
    }
    return String(value)
  }
  if (typeof value === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalString(v)).join(',') + ']'
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).sort(byCodeUnit)
    return (
      '{' +
      keys
        .map((k) => JSON.stringify(k) + ':' + canonicalString(obj[k]))
        .join(',') +
      '}'
    )
  }
  throw new TypeError(`canonical-JSON: unsupported type ${typeof value}`)
}

function check(value: unknown): void {
  if (value === null || typeof value === 'boolean') return
  if (typeof value === 'string') {
    rejectLoneSurrogates(value)
    return
  }
  if (typeof value === 'number') {
    // Number.isSafeInteger (not isInteger): reject floats AND integers outside
    // ±(2^53-1), matching canonicalString() and the Go/Rust/C#/Python ports, so
    // this validator never accepts material the encoder would reject.
    if (!Number.isSafeInteger(value)) {
      throw new TypeError(
        'canonical-JSON: only safe integers (|n| <= 2^53-1) are supported in v1',
      )
    }
    return
  }
  if (Array.isArray(value)) {
    value.forEach(check)
    return
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (typeof k !== 'string') throw new TypeError('non-string key')
      rejectLoneSurrogates(k)
      check(v)
    }
    return
  }
  throw new TypeError(`canonical-JSON: unsupported type ${typeof value}`)
}
