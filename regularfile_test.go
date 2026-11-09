package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectRegularFileMissing(t *testing.T) {
	state := inspectRegularFile(filepath.Join(t.TempDir(), "absent.jar"))
	if state.Exists || state.trustable() {
		t.Fatalf("不存在的文件不应被信任: %+v", state)
	}
}

func TestInspectRegularFileNormal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "lib.jar")
	if err := os.WriteFile(p, []byte("jar-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	state := inspectRegularFile(p)
	if !state.trustable() || state.Size != 9 {
		t.Fatalf("普通文件应返回真实大小: %+v", state)
	}
}

func TestInspectRegularFileSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside.jar")
	if err := os.WriteFile(outside, []byte("attacker"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "lib.jar")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("当前环境不支持创建符号链接: %v", err)
	}
	state := inspectRegularFile(link)
	if state.trustable() || state.Reason != "symlink" {
		t.Fatalf("符号链接不应被信任: %+v", state)
	}
	if describeUntrustedFile(state, link) == "" {
		t.Fatalf("符号链接应给出拒绝说明")
	}
}

func TestInspectRegularFileDirectory(t *testing.T) {
	state := inspectRegularFile(t.TempDir())
	if state.trustable() || state.Reason != "special" {
		t.Fatalf("目录不应被当作可信任文件: %+v", state)
	}
}
