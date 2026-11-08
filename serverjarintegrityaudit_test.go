package main

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const jvrSample = "PK\x03\x04sample-server-jar-bytes"

func jvrWriteJar(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, jvrJarName)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write jar: %v", err)
	}
	sum := sha1.Sum([]byte(content))
	return hex.EncodeToString(sum[:])
}

func jvrHas(a *JarIntegrityAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestJarIntegrityMatch(t *testing.T) {
	dir := t.TempDir()
	digest := jvrWriteJar(t, dir, jvrSample)
	if err := os.WriteFile(filepath.Join(dir, jvrSidecarName), []byte(digest+"\n"), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	a := AuditServerJarIntegrity(dir)
	if a.HasWarnings() {
		t.Fatalf("哈希一致不应报警: %v", a.Describe())
	}
	if a.Digest != digest {
		t.Fatalf("摘要应为 %s，实际 %s", digest, a.Digest)
	}
}

func TestJarIntegrityMissing(t *testing.T) {
	a := AuditServerJarIntegrity(t.TempDir())
	if !jvrHas(a, jvrMiss) || !a.Blocking() {
		t.Fatalf("缺少 jar 应阻断: %v", a.Describe())
	}
}

func TestJarIntegrityEmptyDir(t *testing.T) {
	a := AuditServerJarIntegrity("")
	if !jvrHas(a, jvrMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
}

func TestJarIntegrityEmptyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, jvrJarName), nil, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditServerJarIntegrity(dir)
	if !jvrHas(a, jvrEmpty) || !a.Blocking() {
		t.Fatalf("空 jar 应阻断: %v", a.Describe())
	}
}

func TestJarIntegritySidecarMissing(t *testing.T) {
	dir := t.TempDir()
	jvrWriteJar(t, dir, jvrSample)
	a := AuditServerJarIntegrity(dir)
	if !jvrHas(a, jvrSidecarMiss) {
		t.Fatalf("缺少校验文件应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("缺少校验文件不应阻断: %v", a.Describe())
	}
}

func TestJarIntegrityMismatch(t *testing.T) {
	dir := t.TempDir()
	jvrWriteJar(t, dir, jvrSample)
	if err := os.WriteFile(filepath.Join(dir, jvrSidecarName), []byte(strings.Repeat("a", 40)), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	a := AuditServerJarIntegrity(dir)
	if !jvrHas(a, jvrDigest) || !a.Blocking() {
		t.Fatalf("哈希不符应阻断: %v", a.Describe())
	}
}

func TestJarIntegrityMalformedSidecar(t *testing.T) {
	dir := t.TempDir()
	jvrWriteJar(t, dir, jvrSample)
	if err := os.WriteFile(filepath.Join(dir, jvrSidecarName), []byte("not-a-sha1"), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	a := AuditServerJarIntegrity(dir)
	if !jvrHas(a, jvrSidecarForm) || !a.Blocking() {
		t.Fatalf("校验文件格式错误应阻断: %v", a.Describe())
	}
}

func TestJarIntegrityUppercaseSidecar(t *testing.T) {
	dir := t.TempDir()
	digest := jvrWriteJar(t, dir, jvrSample)
	if err := os.WriteFile(filepath.Join(dir, jvrSidecarName), []byte(strings.ToUpper(digest)), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	a := AuditServerJarIntegrity(dir)
	if a.HasWarnings() {
		t.Fatalf("大写哈希应视为一致: %v", a.Describe())
	}
}

func TestJarIntegritySidecarWithFilename(t *testing.T) {
	dir := t.TempDir()
	digest := jvrWriteJar(t, dir, jvrSample)
	if err := os.WriteFile(filepath.Join(dir, jvrSidecarName), []byte(digest+"  server.jar\n"), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	a := AuditServerJarIntegrity(dir)
	if a.HasWarnings() {
		t.Fatalf("带文件名的校验行应可解析: %v", a.Describe())
	}
}

func TestJarIntegrityDescribe(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerJarIntegrity(dir)
	if !strings.Contains(a.Describe(), jvrMiss) {
		t.Fatalf("描述应含原因键: %s", a.Describe())
	}
}
