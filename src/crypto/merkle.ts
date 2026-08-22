/**
 * A binary Merkle tree over field elements, SHA-256.
 *
 * FRI's commitment is a Merkle root, and its openings are Merkle paths - which
 * is the whole reason FRI is post-quantum: nothing here rests on a discrete log
 * or a pairing, only on a hash being collision-resistant. Grover halves the
 * effective security of a hash, which is why post-quantum hash-based
 * constructions reach for 256-bit digests; it does not break them the way
 * Shor breaks the two schemes above.
 *
 * Leaves are PAIRS. FRI always opens f(x) and f(-x) together, so putting both
 * in one leaf halves the number of authentication paths in the proof. That is
 * what real FRI implementations do, and it is why the size comparison on this
 * page is a fair one.
 *
 * Domain separation: leaves are hashed with a 0x00 prefix and internal nodes
 * with 0x01, so no internal node can be passed off as a leaf.
 */
import { sha256 } from '@noble/hashes/sha2.js'
import { frToBytes } from './fr.js'
import { bytesToHex } from './bls.js'

export const MERKLE_DIGEST_BYTES = 32

function concat(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

export function hashLeafPair(lo: bigint, hi: bigint): Uint8Array {
  return sha256(concat([new Uint8Array([0x00]), frToBytes(lo), frToBytes(hi)]))
}

export function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concat([new Uint8Array([0x01]), left, right]))
}

export interface MerkleTree {
  /** levels[0] are the leaves; the last level is a single root. */
  readonly levels: readonly (readonly Uint8Array[])[]
  readonly root: Uint8Array
  readonly leafCount: number
}

/**
 * Build a tree whose leaf j commits to (values[j], values[j + half]).
 *
 * `values.length` must be a power of two of at least 2, so `half` is exact and
 * the tree is perfect - no padding rules, no second-preimage games with an odd
 * final node.
 */
export function buildPairTree(values: readonly bigint[]): MerkleTree {
  const n = values.length
  if (n < 2 || (n & (n - 1)) !== 0) throw new RangeError('pair tree needs a power-of-two length >= 2')
  const half = n / 2
  let level: Uint8Array[] = []
  for (let j = 0; j < half; j++) level.push(hashLeafPair(values[j], values[j + half]))
  const levels: Uint8Array[][] = [level]
  while (level.length > 1) {
    const next: Uint8Array[] = []
    for (let i = 0; i < level.length; i += 2) next.push(hashNode(level[i], level[i + 1]))
    levels.push(next)
    level = next
  }
  return { levels, root: level[0], leafCount: half }
}

export interface MerkleOpening {
  readonly index: number
  readonly lo: bigint
  readonly hi: bigint
  readonly path: readonly Uint8Array[]
}

export function openPair(tree: MerkleTree, values: readonly bigint[], index: number): MerkleOpening {
  const half = values.length / 2
  if (!Number.isInteger(index) || index < 0 || index >= half) throw new RangeError('leaf index out of range')
  const path: Uint8Array[] = []
  let idx = index
  for (let level = 0; level < tree.levels.length - 1; level++) {
    const sibling = idx ^ 1
    path.push(tree.levels[level][sibling])
    idx >>= 1
  }
  return { index, lo: values[index], hi: values[index + half], path }
}

/** Recompute the root from an opening. Returns false on any mismatch. */
export function verifyOpening(root: Uint8Array, opening: MerkleOpening, leafCount: number): boolean {
  if (opening.index < 0 || opening.index >= leafCount) return false
  const expectedDepth = Math.log2(leafCount)
  if (!Number.isInteger(expectedDepth) || opening.path.length !== expectedDepth) return false
  let node = hashLeafPair(opening.lo, opening.hi)
  let idx = opening.index
  for (const sibling of opening.path) {
    node = (idx & 1) === 0 ? hashNode(node, sibling) : hashNode(sibling, node)
    idx >>= 1
  }
  return bytesToHex(node) === bytesToHex(root)
}

export function rootHex(tree: MerkleTree): string {
  return bytesToHex(tree.root)
}
