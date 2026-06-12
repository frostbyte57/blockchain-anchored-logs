package logintegrity

import (
	"crypto/rand"
	"crypto/sha256"
)

const NonceSize = 16

type Digest [sha256.Size]byte

type Entry struct {
	RawLine string
	Nonce   []byte
}

func NewEntry(rawLine string) (Entry, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return Entry{}, err
	}

	return Entry{
		RawLine: rawLine,
		Nonce:   nonce,
	}, nil
}

func NewEntryWithNonce(rawLine string, nonce []byte) Entry {
	return Entry{
		RawLine: rawLine,
		Nonce:   cloneBytes(nonce),
	}
}

func EntriesFromLines(lines []string) ([]Entry, error) {
	entries := make([]Entry, len(lines))
	for i, line := range lines {
		entry, err := NewEntry(line)
		if err != nil {
			return nil, err
		}
		entries[i] = entry
	}
	return entries, nil
}

func HashRawLine(rawLine string) Digest {
	return sha256.Sum256([]byte(rawLine))
}

func HashLogEntry(rawLine string, nonce []byte) Digest {
	data := make([]byte, 0, len(nonce)+len(rawLine))
	data = append(data, nonce...)
	data = append(data, []byte(rawLine)...)
	return sha256.Sum256(data)
}

func (e Entry) Hash() Digest {
	return HashLogEntry(e.RawLine, e.Nonce)
}

func HashEntries(entries []Entry) []Digest {
	hashes := make([]Digest, len(entries))
	for i, entry := range entries {
		hashes[i] = entry.Hash()
	}
	return hashes
}

func cloneBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
