# blockchain-anchored-logs

A Go project for hashing log entries, grouping them into a Merkle tree, and verifying that entries have not been altered.

## Structure

```text
cmd/loganchor/              CLI entrypoint
internal/logintegrity/      salted log entry hashing, Merkle tree, proofs, verifier
test/                       external behavior tests
```

`internal/logintegrity` is where the core product logic lives. It is intentionally kept separate from the CLI so later phases can add persistence, blockchain anchoring, or an API without mixing those concerns into the hashing and proof code.

## Run tests

```bash
go test ./...
```

## Try the CLI

```bash
printf "user=alice action=login\nuser=bob action=download\n" | go run ./cmd/loganchor
```
