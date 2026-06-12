package logintegrity

type Batch struct {
	entries []Entry
	tree    *Tree
}

func NewBatch(entries []Entry) (*Batch, error) {
	copied := cloneEntries(entries)

	tree, err := NewTree(HashEntries(copied))
	if err != nil {
		return nil, err
	}

	return &Batch{
		entries: copied,
		tree:    tree,
	}, nil
}

func BatchFromLines(lines []string) (*Batch, error) {
	entries, err := EntriesFromLines(lines)
	if err != nil {
		return nil, err
	}
	return NewBatch(entries)
}

func (b *Batch) Root() Digest {
	return b.tree.Root()
}

func (b *Batch) Entries() []Entry {
	return cloneEntries(b.entries)
}

func (b *Batch) Proof(index int) ([]ProofStep, error) {
	return b.tree.Proof(index)
}

func (b *Batch) Verify(entry Entry, proof []ProofStep) bool {
	return VerifyEntry(entry, proof, b.Root())
}

func cloneEntries(entries []Entry) []Entry {
	copied := make([]Entry, len(entries))
	for i, entry := range entries {
		copied[i] = NewEntryWithNonce(entry.RawLine, entry.Nonce)
	}
	return copied
}
