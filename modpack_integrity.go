package main

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func verifyModrinthFile(path string, hashes map[string]string) error {
	if len(hashes) == 0 {
		return nil
	}
	alg := ""
	want := ""
	if h := hashes["sha1"]; len(h) == 40 {
		alg, want = "sha1", h
	} else if h := hashes["sha512"]; len(h) == 128 {
		alg, want = "sha512", h
	}
	if alg == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var sum []byte
	if alg == "sha1" {
		d := sha1.New()
		if _, err := io.Copy(d, f); err != nil {
			return err
		}
		sum = d.Sum(nil)
	} else {
		d := sha512.New()
		if _, err := io.Copy(d, f); err != nil {
			return err
		}
		sum = d.Sum(nil)
	}
	if hex.EncodeToString(sum) != strings.ToLower(want) {
		return fmt.Errorf("哈希校验失败(%s): %s", alg, filepath.Base(path))
	}
	return nil
}
