package main

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"blockchain-anchored-logs/internal/logintegrity"
)

func main() {
	lines, err := readLines(os.Args[1:], os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "no log lines provided")
		os.Exit(1)
	}

	batch, err := logintegrity.BatchFromLines(lines)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("root=%x\n", batch.Root())
	for i, entry := range batch.Entries() {
		fmt.Printf("entry=%d nonce=%x hash=%x\n", i, entry.Nonce, entry.Hash())
	}
}

func readLines(paths []string, stdin io.Reader) ([]string, error) {
	if len(paths) == 0 {
		return scanLines(stdin)
	}

	var lines []string
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}

		fileLines, scanErr := scanLines(file)
		closeErr := file.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("read %s: %w", path, scanErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", path, closeErr)
		}

		lines = append(lines, fileLines...)
	}

	return lines, nil
}

func scanLines(reader io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}
