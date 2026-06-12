package logintegrity

import (
	"crypto/sha256"
	"errors"
)

var ErrEmptyLeaves = errors.New("merkle tree needs at least one leaf")

type Tree struct {
	layers [][]Digest
}

func NewTree(leaves []Digest) (*Tree, error) {
	if len(leaves) == 0 {
		return nil, ErrEmptyLeaves
	}

	layers := [][]Digest{cloneDigests(leaves)}
	for len(layers[len(layers)-1]) > 1 {
		layers = append(layers, nextLayer(layers[len(layers)-1]))
	}

	return &Tree{layers: layers}, nil
}

func BuildMerkleTree(leaves []Digest) ([][]Digest, error) {
	tree, err := NewTree(leaves)
	if err != nil {
		return nil, err
	}
	return tree.Layers(), nil
}

func MerkleRoot(leaves []Digest) (Digest, error) {
	tree, err := NewTree(leaves)
	if err != nil {
		return Digest{}, err
	}
	return tree.Root(), nil
}

func (t *Tree) Root() Digest {
	top := t.layers[len(t.layers)-1]
	return top[0]
}

func (t *Tree) Layers() [][]Digest {
	layers := make([][]Digest, len(t.layers))
	for i, layer := range t.layers {
		layers[i] = cloneDigests(layer)
	}
	return layers
}

func nextLayer(layer []Digest) []Digest {
	next := make([]Digest, 0, (len(layer)+1)/2)
	for i := 0; i < len(layer); i += 2 {
		left := layer[i]
		right := left
		if i+1 < len(layer) {
			right = layer[i+1]
		}
		next = append(next, hashPair(left, right))
	}
	return next
}

func hashPair(left, right Digest) Digest {
	data := make([]byte, 0, sha256.Size*2)
	data = append(data, left[:]...)
	data = append(data, right[:]...)
	return sha256.Sum256(data)
}

func cloneDigests(src []Digest) []Digest {
	dst := make([]Digest, len(src))
	copy(dst, src)
	return dst
}
