import { describe, expect, it } from 'vitest'
import { frRandom } from './fr.js'
import { buildPairTree, hashLeafPair, hashNode, openPair, rootHex, verifyOpening } from './merkle.js'
import { bytesToHex } from './bls.js'

const VALUES = Array.from({ length: 16 }, (_, i) => BigInt(i + 1) * 1000n)

describe('the pair Merkle tree', () => {
  it('halves the leaf count by putting f(x) and f(-x) in one leaf', () => {
    const tree = buildPairTree(VALUES)
    expect(tree.leafCount).toBe(VALUES.length / 2)
    expect(tree.levels[0].length).toBe(VALUES.length / 2)
    expect(tree.levels[tree.levels.length - 1].length).toBe(1)
    expect(tree.levels.length).toBe(Math.log2(VALUES.length / 2) + 1)
  })

  it('every opening verifies against the root', () => {
    const tree = buildPairTree(VALUES)
    for (let i = 0; i < tree.leafCount; i++) {
      const opening = openPair(tree, VALUES, i)
      expect(opening.lo).toBe(VALUES[i])
      expect(opening.hi).toBe(VALUES[i + VALUES.length / 2])
      expect(verifyOpening(tree.root, opening, tree.leafCount)).toBe(true)
    }
  })

  it('rejects a tampered value', () => {
    const tree = buildPairTree(VALUES)
    const opening = openPair(tree, VALUES, 3)
    expect(verifyOpening(tree.root, { ...opening, lo: opening.lo + 1n }, tree.leafCount)).toBe(false)
    expect(verifyOpening(tree.root, { ...opening, hi: opening.hi + 1n }, tree.leafCount)).toBe(false)
  })

  it('rejects a tampered path', () => {
    const tree = buildPairTree(VALUES)
    const opening = openPair(tree, VALUES, 3)
    const broken = opening.path.map((h, i) => (i === 1 ? new Uint8Array(32) : h))
    expect(verifyOpening(tree.root, { ...opening, path: broken }, tree.leafCount)).toBe(false)
  })

  it('rejects a path of the wrong length', () => {
    const tree = buildPairTree(VALUES)
    const opening = openPair(tree, VALUES, 3)
    expect(verifyOpening(tree.root, { ...opening, path: opening.path.slice(1) }, tree.leafCount)).toBe(false)
  })

  it('rejects an out-of-range index', () => {
    const tree = buildPairTree(VALUES)
    const opening = openPair(tree, VALUES, 3)
    expect(verifyOpening(tree.root, { ...opening, index: 99 }, tree.leafCount)).toBe(false)
    expect(() => openPair(tree, VALUES, tree.leafCount)).toThrow(/out of range/)
  })

  it('rejects an opening replayed at the wrong index', () => {
    const tree = buildPairTree(VALUES)
    const opening = openPair(tree, VALUES, 3)
    expect(verifyOpening(tree.root, { ...opening, index: 4 }, tree.leafCount)).toBe(false)
  })

  it('separates leaf hashes from internal-node hashes', () => {
    // A leaf and an internal node over the same 64 bytes must differ, or an
    // internal node could be passed off as a leaf.
    const a = new Uint8Array(32).fill(1)
    const b = new Uint8Array(32).fill(2)
    expect(bytesToHex(hashNode(a, b))).not.toBe(bytesToHex(hashLeafPair(1n, 2n)))
  })

  it('two different value sets give different roots', () => {
    const other = VALUES.map((v, i) => (i === 7 ? v + 1n : v))
    expect(rootHex(buildPairTree(VALUES))).not.toBe(rootHex(buildPairTree(other)))
  })

  it('the same values always give the same root', () => {
    const random = Array.from({ length: 8 }, () => frRandom())
    expect(rootHex(buildPairTree(random))).toBe(rootHex(buildPairTree(random.slice())))
  })

  it('refuses a non-power-of-two input', () => {
    expect(() => buildPairTree([1n, 2n, 3n])).toThrow(/power-of-two/)
    expect(() => buildPairTree([1n])).toThrow(/power-of-two/)
  })
})
