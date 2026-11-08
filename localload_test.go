package main

// localload_test.go 覆盖本地有界读取：readBoundedFile（唯一原语）与
// readLocalJSONBounded（在其上的 JSON 封装）。重点验证多读 1 字节的超限判定、
// 损坏内容不误用、非正上限拒绝、符号链接拒绝。

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadBoundedFileOK(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "options.txt")
	want := []byte("lang:zh_CN\n")
	if err := os.WriteFile(p, want, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readBoundedFile(p, 4096)
	if err != nil {
		t.Fatalf("正常读取失败: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("内容不一致: %q", got)
	}
}

func TestReadBoundedFileExactlyAtLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "exact.bin")
	if err := os.WriteFile(p, make([]byte, 64), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readBoundedFile(p, 64)
	if err != nil {
		t.Fatalf("恰好等于上限不应报错: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("长度应恰好为 64，实际 %d", len(got))
	}
}

func TestReadBoundedFileTooLarge(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(p, make([]byte, 128), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(p, 32); !errors.Is(err, errLocalFileTooLarge) {
		t.Fatalf("应返回 errLocalFileTooLarge，实际 %v", err)
	}
}

func TestReadBoundedFileRejectsNonPositiveLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(p, 0); err == nil {
		t.Fatal("非正上限必须报错")
	}
}

func TestReadBoundedFileMissing(t *testing.T) {
	if _, err := readBoundedFile(filepath.Join(t.TempDir(), "x.txt"), 1024); err == nil {
		t.Fatal("文件不存在应报错")
	}
}

func TestReadBoundedFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")
	if err := os.WriteFile(target, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		// Windows 上无 SeCreateSymbolicLinkPrivilege 时建链失败，跳过该项。
		t.Skipf("当前环境无法创建符号链接，跳过: %v", err)
	}
	if _, err := readBoundedFile(link, 1024); err == nil {
		t.Fatal("读取符号链接必须被拒绝")
	}
}

func TestReadLocalJSONBoundedOK(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "v.json")
	if err := os.WriteFile(p, []byte(`{"name":"ok","version":3}`), 0600); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := readLocalJSONBounded(p, &got, 0, "测试版本 JSON"); err != nil {
		t.Fatalf("正常文件应读取成功: %v", err)
	}
	if got["name"] != "ok" || got["version"] != float64(3) {
		t.Fatalf("解析内容错误: %#v", got)
	}
}

func TestReadLocalJSONBoundedTooLarge(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.json")
	if err := os.WriteFile(p, make([]byte, 200), 0600); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	err := readLocalJSONBounded(p, &got, 64, "测试大 JSON")
	if !errors.Is(err, errLocalFileTooLarge) {
		t.Fatalf("应包装 errLocalFileTooLarge，实际 %v", err)
	}
}

func TestReadLocalJSONBoundedMissing(t *testing.T) {
	var got map[string]any
	if err := readLocalJSONBounded(filepath.Join(t.TempDir(), "nope.json"), &got, 0, ""); err == nil {
		t.Fatal("文件不存在应返回错误")
	}
}

func TestReadLocalJSONBoundedMalformed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte(`{not json`), 0600); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := readLocalJSONBounded(p, &got, 0, ""); err == nil {
		t.Fatal("损坏 JSON 应返回错误")
	}
}
