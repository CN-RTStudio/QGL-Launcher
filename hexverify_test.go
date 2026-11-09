package main

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	return p
}

func TestEqualHexDigestIgnoresCase(t *testing.T) {
	if !equalHexDigest("abcdef", "ABCDEF") {
		t.Fatalf("大小写不同的同一摘要应判定相等")
	}
	if !equalHexDigest("  abcdef\n", "abcdef") {
		t.Fatalf("首尾空白应被忽略")
	}
	if equalHexDigest("abcdef", "abcdee") {
		t.Fatalf("不同摘要不得判定相等")
	}
	if equalHexDigest("", "abc") {
		t.Fatalf("空摘要不得匹配非空摘要")
	}
}

func TestFileSHA1Matches(t *testing.T) {
	p := writeTempFile(t, "cosy")
	sum := sha1.Sum([]byte("cosy"))
	want := hex.EncodeToString(sum[:])
	if !fileSHA1Matches(p, want) {
		t.Fatalf("正确摘要应通过")
	}
	if !fileSHA1Matches(p, "  "+want+"  ") {
		t.Fatalf("带空白摘要应通过")
	}
	if fileSHA1Matches(p, "deadbeef") {
		t.Fatalf("错误摘要必须拒绝")
	}
	if fileSHA1Matches(filepath.Join(t.TempDir(), "missing.bin"), want) {
		t.Fatalf("文件不存在必须拒绝")
	}
}

func TestVerifyFileDigest(t *testing.T) {
	p := writeTempFile(t, "launcher")
	sum := sha1.Sum([]byte("launcher"))
	want := hex.EncodeToString(sum[:])
	got, err := verifyFileDigest(p, "sha1", want)
	if err != nil || got != "" {
		t.Fatalf("匹配时应返回空串与 nil，实际 got=%q err=%v", got, err)
	}
	got, err = verifyFileDigest(p, "sha1", "0011")
	if err != nil || got != want {
		t.Fatalf("不匹配时应返回实际摘要，实际 got=%q err=%v", got, err)
	}
	if _, err := verifyFileDigest(p, "md5", "xx"); err == nil {
		t.Fatalf("未知算法必须报错")
	}
}
