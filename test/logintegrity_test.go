package test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"blockchain-anchored-logs/internal/logintegrity"
)

func TestHashRawLineUsesSHA256OfLineBytes(t *testing.T) {
	got := logintegrity.HashRawLine("user=alice action=login")
	want := logintegrity.Digest{
		0xd5, 0x49, 0x65, 0x10, 0x7a, 0xad, 0x6a, 0x1a,
		0xe6, 0xc0, 0xdc, 0x1a, 0xb6, 0xd2, 0xac, 0x9f,
		0x26, 0x95, 0xdd, 0xfb, 0x5b, 0xda, 0x35, 0x52,
		0x7c, 0xa8, 0x13, 0xd8, 0xff, 0xb3, 0x9d, 0x6e,
	}

	if got != want {
		t.Fatalf("hash mismatch: got %x want %x", got, want)
	}
}

func TestNewEntryAddsRandomNonce(t *testing.T) {
	first, err := logintegrity.NewEntry("same low entropy line")
	if err != nil {
		t.Fatal(err)
	}

	second, err := logintegrity.NewEntry("same low entropy line")
	if err != nil {
		t.Fatal(err)
	}

	if len(first.Nonce) != logintegrity.NonceSize || len(second.Nonce) != logintegrity.NonceSize {
		t.Fatalf("nonce sizes: got %d and %d", len(first.Nonce), len(second.Nonce))
	}

	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Fatal("expected different nonces")
	}

	if first.Hash() == second.Hash() {
		t.Fatal("same line with different nonce should hash differently")
	}
}

func TestBatchCopiesEntries(t *testing.T) {
	entries := []logintegrity.Entry{
		logintegrity.NewEntryWithNonce("one", []byte("nonce-0000000001")),
		logintegrity.NewEntryWithNonce("two", []byte("nonce-0000000002")),
	}

	batch, err := logintegrity.NewBatch(entries)
	if err != nil {
		t.Fatal(err)
	}

	entries[0].RawLine = "tampered before verification"
	entries[0].Nonce[0] = 'x'

	stored := batch.Entries()
	if stored[0].RawLine != "one" || stored[0].Nonce[0] == 'x' {
		t.Fatal("batch should keep its own copy of entries")
	}
}

func TestMerkleRootDuplicatesOddLeaf(t *testing.T) {
	entries := []logintegrity.Entry{
		logintegrity.NewEntryWithNonce("one", []byte("nonce-0000000001")),
		logintegrity.NewEntryWithNonce("two", []byte("nonce-0000000002")),
		logintegrity.NewEntryWithNonce("three", []byte("nonce-0000000003")),
	}
	leaves := logintegrity.HashEntries(entries)

	got, err := logintegrity.MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}

	left := hashPair(leaves[0], leaves[1])
	right := hashPair(leaves[2], leaves[2])
	want := hashPair(left, right)

	if got != want {
		t.Fatalf("root mismatch: got %x want %x", got, want)
	}
}

func TestProofVerifiesRealEntryAndRejectsTampering(t *testing.T) {
	entries := []logintegrity.Entry{
		logintegrity.NewEntryWithNonce("2026-06-12T10:00:00Z user=alice action=login", []byte("nonce-0000000001")),
		logintegrity.NewEntryWithNonce("2026-06-12T10:01:00Z user=bob action=download", []byte("nonce-0000000002")),
		logintegrity.NewEntryWithNonce("2026-06-12T10:02:00Z user=carol action=logout", []byte("nonce-0000000003")),
	}

	batch, err := logintegrity.NewBatch(entries)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := batch.Proof(1)
	if err != nil {
		t.Fatal(err)
	}

	if !batch.Verify(entries[1], proof) {
		t.Fatal("expected real entry proof to verify")
	}

	tampered := entries[1]
	tampered.RawLine = "2026-06-12T10:01:00Z user=bob action=downloads"

	if batch.Verify(tampered, proof) {
		t.Fatal("expected tampered entry to fail verification")
	}
}

func TestProofForOddLastLeafVerifies(t *testing.T) {
	entries := []logintegrity.Entry{
		logintegrity.NewEntryWithNonce("one", []byte("nonce-0000000001")),
		logintegrity.NewEntryWithNonce("two", []byte("nonce-0000000002")),
		logintegrity.NewEntryWithNonce("three", []byte("nonce-0000000003")),
	}
	leaves := logintegrity.HashEntries(entries)

	root, err := logintegrity.MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := logintegrity.GenerateProof(leaves, 2)
	if err != nil {
		t.Fatal(err)
	}

	if len(proof) != 2 {
		t.Fatalf("proof length: got %d want 2", len(proof))
	}

	if proof[0].Side != logintegrity.Right || proof[0].Hash != leaves[2] {
		t.Fatal("first proof step should duplicate last leaf")
	}

	if !logintegrity.VerifyEntry(entries[2], proof, root) {
		t.Fatal("expected odd last leaf proof to verify")
	}
}

func TestGenerateProofRejectsBadInput(t *testing.T) {
	if _, err := logintegrity.GenerateProof(nil, 0); !errors.Is(err, logintegrity.ErrEmptyLeaves) {
		t.Fatalf("expected ErrEmptyLeaves, got %v", err)
	}

	entries := []logintegrity.Entry{
		logintegrity.NewEntryWithNonce("only", []byte("nonce-0000000001")),
	}
	if _, err := logintegrity.GenerateProof(logintegrity.HashEntries(entries), 1); !errors.Is(err, logintegrity.ErrIndexOutOfRange) {
		t.Fatalf("expected ErrIndexOutOfRange, got %v", err)
	}
}

func TestVerifierRejectsBadProofSide(t *testing.T) {
	entry := logintegrity.NewEntryWithNonce("line", []byte("nonce-0000000001"))
	root, err := logintegrity.MerkleRoot([]logintegrity.Digest{entry.Hash()})
	if err != nil {
		t.Fatal(err)
	}

	if logintegrity.VerifyEntry(entry, []logintegrity.ProofStep{{Side: "middle"}}, root) {
		t.Fatal("expected bad proof side to fail")
	}
}

func hashPair(left, right logintegrity.Digest) logintegrity.Digest {
	data := make([]byte, 0, sha256.Size*2)
	data = append(data, left[:]...)
	data = append(data, right[:]...)
	return sha256.Sum256(data)
}
