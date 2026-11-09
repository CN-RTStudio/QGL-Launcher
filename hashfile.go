package main

import (
	"crypto"
	"encoding/hex"
	"io"
	"os"
)

func hashFileHex(algo crypto.Hash, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := algo.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
