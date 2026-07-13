package store

// Tamper-EVIDENT op-log hash chain.
//
// Every stored op carries a SHA-256 chain hash that binds it to (its vault, its
// seq, ALL prior ops in that vault, and its opaque blob). Because each op's hash
// folds in the previous op's hash, any later insertion, deletion, reordering, or
// modification of a stored op changes every subsequent hash — so a full walk
// (VerifyChain) detects it at the first broken link.
//
// This is tamper-EVIDENT, NOT tamper-PROOF. It lets an honest reader DETECT
// after-the-fact corruption of the stored bytes; it does NOT prevent a malicious
// server from rewriting the whole chain, nor is it an append-only/Byzantine/
// notarized log. A dishonest server can also lie about VerifyChain's result: the
// only trustworthy verification is CLIENT-SIDE, recomputing this same chain from
// the per-op hashes the server returns. The chain is computed over the OPAQUE
// ciphertext blob only; it fingerprints ciphertext and never touches plaintext,
// so it does not weaken the server's zero-knowledge property.
//
// chainHash is the ONE canonical definition shared by all three backends and the
// verifier, so the same (vaultID, blobs) input yields an identical hash sequence
// on Mem, File, and Postgres.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
)

// chainDomain is the fixed ASCII domain-separation tag hashed first in every
// chain link. Bumping it (…-v2) is a clean break that invalidates every prior
// hash, so keep it byte-for-byte stable while the format is v1.
const chainDomain = "sigil-oplog-chain-v1"

// chainHash returns the chain hash of one op:
//
//	SHA-256( chainDomain || uint32_be(len(vaultID)) || vaultID
//	         || uint64_be(seq) || prevHash[32] || blob )
//
// The uint32 length prefix on vaultID makes the encoding UNAMBIGUOUS: no two
// distinct (vaultID, blob) pairs can produce the same byte stream by shifting the
// vaultID/blob boundary. prevHash is the previous op's chain hash, or the 32 zero
// bytes for the genesis op (seq == 1). It is deterministic and identical across
// backends for identical input.
func chainHash(vaultID string, seq uint64, prevHash [32]byte, blob []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(chainDomain))

	var num [8]byte
	binary.BigEndian.PutUint32(num[:4], uint32(len(vaultID)))
	h.Write(num[:4])
	h.Write([]byte(vaultID))

	binary.BigEndian.PutUint64(num[:], seq)
	h.Write(num[:])

	h.Write(prevHash[:])
	h.Write(blob)

	var out [32]byte
	h.Sum(out[:0])
	return out
}

// VerifyResult reports the outcome of walking a vault's hash chain.
//
// When OK is true the chain is intact: Count ops verified and TipHash is the
// final op's hash (the 32 zero bytes for an empty vault). When OK is false the
// chain is broken: BrokenAtSeq is the seq of the FIRST op whose stored hash does
// not match its recomputation, Count is the number of ops present, and TipHash is
// left zero (there is no trustworthy tip past a break).
type VerifyResult struct {
	OK          bool
	Count       uint64
	TipHash     [32]byte
	BrokenAtSeq uint64 // 0 when OK
}

// verifyChain recomputes the hash chain over ops — which MUST be every op of one
// vault in ascending Seq order, starting at the vault's first op (seq 1) — and
// compares each recomputed hash to the stored Op.Hash. It is the shared core of
// every backend's VerifyChain. On the first mismatch it stops and reports the
// broken seq; otherwise it reports OK with the tip hash.
func verifyChain(vaultID string, ops []Op) VerifyResult {
	var prev [32]byte
	for _, op := range ops {
		want := chainHash(vaultID, op.Seq, prev, op.Blob)
		if want != op.Hash {
			return VerifyResult{OK: false, Count: uint64(len(ops)), BrokenAtSeq: op.Seq}
		}
		prev = want
	}
	return VerifyResult{OK: true, Count: uint64(len(ops)), TipHash: prev}
}

// verifyChainVia is the shared VerifyChain body: pull the vault's full op history
// (honouring ctx) and walk it. Every backend delegates here so the walk is
// identical everywhere; only how the ops are fetched differs (all use Since(…,0)).
func verifyChainVia(ctx context.Context, l VaultLog, vaultID string) (VerifyResult, error) {
	ops, err := l.Since(ctx, vaultID, 0)
	if err != nil {
		return VerifyResult{}, err
	}
	return verifyChain(vaultID, ops), nil
}
