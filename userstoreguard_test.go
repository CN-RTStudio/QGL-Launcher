package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeStoreFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestReadPrivateStoreJSONValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeStoreFile(t, path, []byte(`{"type":"offline"}`))
	var v struct {
		Type string `json:"type"`
	}
	if err := readPrivateStoreJSON(path, &v, "test"); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if v.Type != "offline" {
		t.Fatalf("unexpected type %q", v.Type)
	}
}

func TestReadPrivateStoreJSONMissing(t *testing.T) {
	var v struct{}
	err := readPrivateStoreJSON(filepath.Join(t.TempDir(), "absent.json"), &v, "test")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestReadPrivateStoreJSONOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.json")
	big := append([]byte(`{"k":"`), make([]byte, privateStoreMaxBytes+64)...)
	big = append(big, []byte(`"}`)...)
	writeStoreFile(t, path, big)
	var v map[string]string
	err := readPrivateStoreJSON(path, &v, "test")
	if !errors.Is(err, errLocalFileTooLarge) {
		t.Fatalf("expected errLocalFileTooLarge, got %v", err)
	}
}

func TestReadPrivateStoreJSONCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	writeStoreFile(t, path, []byte(`{not json`))
	var v struct{}
	if err := readPrivateStoreJSON(path, &v, "test"); err == nil {
		t.Fatal("expected parse error, got nil")
	}
}
