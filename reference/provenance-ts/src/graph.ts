/**
 * Chain DAG verifier — §7 (taint monotonicity) + §8 (acyclicity +
 * closure) + §9 (verifier obligations).
 *
 * Mirrors graph.py. A Chain is a topologically-ordered, closed-under-
 * parents list of receipts. `verifyChain` checks every cross-receipt
 * invariant the spec requires.
 */

import { byCodeUnit } from './canonical.js'
import type { Receipt } from './receipt.js'

export class ChainError extends Error {}

export interface Chain {
  receipts: Receipt[]
  byId: Map<string, Receipt>
}

/**
 * Build + validate a chain from an ordered list of already-verified
 * receipts (verify each JWS with `verify()` first).
 */
export function buildChain(receipts: Receipt[]): Chain {
  const byId = buildByIdMap(receipts)
  for (const r of receipts) {
    checkTaintMonotonicity(r, byId)
  }
  return { receipts, byId }
}

function buildByIdMap(receipts: Receipt[]): Map<string, Receipt> {
  const byId = new Map<string, Receipt>()

  for (const r of receipts) {
    if (byId.has(r.id)) {
      throw new ChainError(`duplicate receipt id in chain: ${r.id}`)
    }
    // Closure under parents (§8): every parent must appear earlier in
    // the topo-ordered list. This also makes cycles unrepresentable.
    for (const p of r.payload.parents) {
      if (!byId.has(p)) {
        throw new ChainError(
          `receipt ${r.id} references parent ${p} not earlier in the chain ` +
            '(topo or closure violation)',
        )
      }
    }
    byId.set(r.id, r)
  }
  return byId
}

function collectParentTaint(r: Receipt, byId: Map<string, Receipt>): Set<string> {
  const parentTaint = new Set<string>()
  for (const p of r.payload.parents) {
    for (const t of byId.get(p)!.payload.taint) parentTaint.add(t)
  }
  return parentTaint
}

function checkTaintMonotonicity(r: Receipt, byId: Map<string, Receipt>): void {
  const parentTaint = collectParentTaint(r, byId)
  const childTaint = new Set(r.payload.taint)

  if (r.payload.operation === 'sanitisation') {
    checkSanitisation(r, parentTaint, childTaint)
  } else {
    checkNonSanitisation(r, parentTaint, childTaint)
  }
}

function checkSanitisation(
  r: Receipt,
  parentTaint: Set<string>,
  childTaint: Set<string>,
): void {
  const corpus = r.payload.corpus ?? ''
  const removed = new Set<string>(
    corpus.startsWith('removed:')
      ? corpus.slice('removed:'.length).split(',').filter((s) => s.length > 0)
      : [],
  )
  const missing = [...parentTaint].filter(
    (t) => !childTaint.has(t) && !removed.has(t),
  )
  if (missing.length > 0) {
    missing.sort(byCodeUnit)
    throw new ChainError(
      `sanitisation receipt ${r.id} dropped tags without declaring ` +
        `them in corpus removed-set: ${missing.join(', ')}`,
    )
  }
}

function checkNonSanitisation(
  r: Receipt,
  parentTaint: Set<string>,
  childTaint: Set<string>,
): void {
  const missing = [...parentTaint].filter((t) => !childTaint.has(t))
  if (missing.length > 0) {
    missing.sort(byCodeUnit)
    throw new ChainError(
      `taint monotonicity violation at ${r.id}: missing ${missing.join(', ')}`,
    )
  }
}
