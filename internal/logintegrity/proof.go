package logintegrity

import (
	"bytes"
	"errors"
)

const (
	Left  = "left"
	Right = "right"
)

var (
	ErrIndexOutOfRange = errors.New("leaf index out of range")
	ErrEntryNotFound   = errors.New("entry not found in leaves")
)

type ProofStep struct {
	Side string
	Hash Digest
}

func GenerateProof(leaves []Digest, index int) ([]ProofStep, error) {
	tree, err := NewTree(leaves)
	if err != nil {
		return nil, err
	}
	return tree.Proof(index)
}

func (t *Tree) Proof(index int) ([]ProofStep, error) {
	if index < 0 || index >= len(t.layers[0]) {
		return nil, ErrIndexOutOfRange
	}

	proof := make([]ProofStep, 0, len(t.layers)-1)
	for _, layer := range t.layers[:len(t.layers)-1] {
		if index%2 == 0 {
			sibling := index + 1
			if sibling >= len(layer) {
				sibling = index
			}
			proof = append(proof, ProofStep{Side: Right, Hash: layer[sibling]})
		} else {
			proof = append(proof, ProofStep{Side: Left, Hash: layer[index-1]})
		}
		index /= 2
	}

	return proof, nil
}

func ProofForEntry(entries []Entry, entry Entry) ([]ProofStep, error) {
	for i, candidate := range entries {
		if sameEntry(candidate, entry) {
			return GenerateProof(HashEntries(entries), i)
		}
	}
	return nil, ErrEntryNotFound
}

func VerifyEntry(entry Entry, proof []ProofStep, claimedRoot Digest) bool {
	current := entry.Hash()

	for _, step := range proof {
		switch step.Side {
		case Left:
			current = hashPair(step.Hash, current)
		case Right:
			current = hashPair(current, step.Hash)
		default:
			return false
		}
	}

	return current == claimedRoot
}

func sameEntry(a, b Entry) bool {
	return a.RawLine == b.RawLine && bytes.Equal(a.Nonce, b.Nonce)
}
