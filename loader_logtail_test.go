package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadLogTailSmallFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "small.log")
	if err := os.WriteFile(p, []byte("hello log"), 0o600); err != nil {
		t.Fatal(err)
	}
	text, truncated, err := readLogTail(p, 1<<20)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if truncated {
		t.Fatal("小文件不应被判定为截断")
	}
	if text != "hello log" {
		t.Fatalf("内容不符: %q", text)
	}
}

func TestReadLogTailTruncatesToTail(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.log")
	body := strings.Repeat("A", 4096) + "TAIL"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	text, truncated, err := readLogTail(p, 1024)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if !truncated {
		t.Fatal("超限文件应被判定为截断")
	}
	if len(text) != 1024 {
		t.Fatalf("应只返回末尾 1024 字节，实际 %d", len(text))
	}
	if !strings.HasSuffix(text, "TAIL") {
		t.Fatal("截断后应保留文件末尾内容")
	}
}

func TestReadLogTailRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("当前环境不支持创建符号链接")
	}
	if _, _, err := readLogTail(link, 1<<20); err == nil {
		t.Fatal("符号链接应被拒绝")
	}
}

func TestReadLogTailRejectsNonPositiveLimit(t *testing.T) {
	if _, _, err := readLogTail(filepath.Join(t.TempDir(), "x.log"), 0); err == nil {
		t.Fatal("maxBytes<=0 应报错")
	}
}
