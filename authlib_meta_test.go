package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha256HexOf(t *testing.T, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestAuthlibMetaRoundTrip(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "authlib-injector.jar")
	data := []byte("FAKE-BUT-VALID-JAR-BYTES")
	if err := os.WriteFile(jar, data, 0o600); err != nil {
		t.Fatalf("写 jar 失败: %v", err)
	}
	want := sha256HexOf(t, data)

	if verifyAuthlibJar(jar, want) {
		t.Fatal("没有侧车时不应判定为可信")
	}
	if err := saveAuthlibMeta(jar, want, int64(len(data))); err != nil {
		t.Fatalf("写侧车失败: %v", err)
	}
	if !verifyAuthlibJar(jar, want) {
		t.Fatal("侧车完整且哈希一致时应通过校验")
	}
}

func TestVerifyAuthlibJarRejectsTamper(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "authlib-injector.jar")
	data := []byte("original bytes")
	want := sha256HexOf(t, data)
	if err := os.WriteFile(jar, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveAuthlibMeta(jar, want, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	// 篡改 jar 内容但尺寸不变：必须被哈希抓到。
	tampered := []byte("original BYTES")
	if len(tampered) != len(data) {
		t.Fatal("测试用例需要等长篡改")
	}
	if err := os.WriteFile(jar, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if verifyAuthlibJar(jar, want) {
		t.Fatal("被篡改的 jar 必须校验失败")
	}
}

func TestVerifyAuthlibJarWrongExpected(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "authlib-injector.jar")
	data := []byte("hello")
	want := sha256HexOf(t, data)
	if err := os.WriteFile(jar, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveAuthlibMeta(jar, want, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	other := sha256HexOf(t, []byte("different"))
	if verifyAuthlibJar(jar, other) {
		t.Fatal("期望哈希与侧车不一致时必须失败")
	}
}

func TestVerifyAuthlibJarSizeMismatch(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "authlib-injector.jar")
	data := []byte("abcdef")
	want := sha256HexOf(t, data)
	if err := os.WriteFile(jar, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// 侧车记录的尺寸是错的：应在廉价预检阶段直接失败。
	if err := saveAuthlibMeta(jar, want, 999); err != nil {
		t.Fatal(err)
	}
	if verifyAuthlibJar(jar, want) {
		t.Fatal("尺寸不一致时必须失败")
	}
}

func TestVerifyAuthlibJarMissing(t *testing.T) {
	dir := t.TempDir()
	if verifyAuthlibJar(filepath.Join(dir, "nope.jar"), strings.Repeat("a", 64)) {
		t.Fatal("jar 不存在时必须失败")
	}
}

func TestVerifyAuthlibJarEmptyHash(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "authlib-injector.jar")
	if err := os.WriteFile(jar, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if verifyAuthlibJar(jar, "") {
		t.Fatal("空的期望哈希必须失败")
	}
}

func TestRemoveAuthlibMeta(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "authlib-injector.jar")
	if err := os.WriteFile(jar, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveAuthlibMeta(jar, strings.Repeat("a", 64), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(authlibMetaPath(jar)); err != nil {
		t.Fatalf("侧车应已写入: %v", err)
	}
	removeAuthlibMeta(jar)
	if _, err := os.Stat(authlibMetaPath(jar)); !os.IsNotExist(err) {
		t.Fatal("侧车应被删除")
	}
}

func TestIsAllowedAuthlibDownloadURL(t *testing.T) {
	good := []string{
		"https://authlib-injector.yushi.moe/artifact/abc.jar",
		"https://bmclapi2.bangbang93.com/mirrors/authlib-injector/artifact/abc.jar",
	}
	for _, u := range good {
		if !isAllowedAuthlibDownloadURL(u) {
			t.Errorf("%s 应被允许", u)
		}
	}
	bad := []string{
		"http://authlib-injector.yushi.moe/artifact/abc.jar",   // 明文 http
		"https://evil.example.com/abc.jar",                     // 非白名单主机
		"https://authlib-injector.yushi.moe.evil.com/x.jar",    // 后缀伪造
		"https://user:pass@authlib-injector.yushi.moe/x.jar",   // 带 userinfo
		"javascript:alert(1)",
	}
	for _, u := range bad {
		if isAllowedAuthlibDownloadURL(u) {
			t.Errorf("%s 应被拒绝", u)
		}
	}
}
