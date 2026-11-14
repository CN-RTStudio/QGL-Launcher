package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrayEmptyDir(t *testing.T) {
	a := AuditServerStraySecrets(t.TempDir())
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("empty dir flagged: %s", a.Describe())
	}
}

func TestStrayMissingDir(t *testing.T) {
	a := AuditServerStraySecrets(filepath.Join(t.TempDir(), "absent"))
	if len(a.Scanned) != 0 {
		t.Fatalf("scanned=%v", a.Scanned)
	}
}

func TestStrayEnvSecretWarns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DB_PASSWORD=hunter2\nAPI_KEY=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := AuditServerStraySecrets(dir)
	if !auditHasReason(a, strayReasonEnvSecret) {
		t.Fatalf("want env-secret, got %v", a.Codes())
	}
	if a.Blocking() {
		t.Fatalf("env secret should warn only")
	}
}

func TestStrayPrivateKeyBlocks(t *testing.T) {
	dir := t.TempDir()
	body := "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(dir, "server.pem"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := AuditServerStraySecrets(dir)
	if !auditHasReason(a, strayReasonPrivateKey) || !a.Blocking() {
		t.Fatalf("want private-key block, got %v", a.Codes())
	}
}

func TestStrayCloudCredentialWarns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "credentials"), []byte("[default]\naws_access_key_id=AKIA\naws_secret_access_key=xyz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := AuditServerStraySecrets(dir)
	if !auditHasReason(a, strayReasonCloudSecret) {
		t.Fatalf("want cloud-credential, got %v", a.Codes())
	}
}

func TestStrayKeystoreWarns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keystore.jks"), []byte("binary-ish"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := AuditServerStraySecrets(dir)
	if !auditHasReason(a, strayReasonKeystore) {
		t.Fatalf("want keystore, got %v", a.Codes())
	}
}

func TestStraySymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.env")
	if err := os.WriteFile(real, []byte("token=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, ".env")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerStraySecrets(dir)
	if !auditHasReason(a, strayReasonSymlink) || !a.Blocking() {
		t.Fatalf("want symlink block, got %v", a.Codes())
	}
}

func TestStrayOversizedWarns(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("A", strayMaxFileBytes+64)
	if err := os.WriteFile(filepath.Join(dir, "big.key"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	a := AuditServerStraySecrets(dir)
	if !auditHasReason(a, strayReasonTooLarge) {
		t.Fatalf("want too-large, got %v", a.Codes())
	}
}

func TestStrayNestedPluginSecret(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "plugins"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugins", ".env"), []byte("token=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := AuditServerStraySecrets(dir)
	found := false
	for _, f := range a.Findings {
		if strings.Contains(f.Path, "plugins") && f.Reason == strayReasonEnvSecret {
			found = true
		}
	}
	if !found {
		t.Fatalf("want plugins/.env env-secret, got %v", a.Findings)
	}
}

func TestStrayWorldReadableWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Skipf("chmod unsupported: %v", err)
	}
	a := AuditServerStraySecrets(dir)
	if !auditHasReason(a, strayReasonWorldReadable) {
		t.Fatalf("want world-readable, got %v", a.Codes())
	}
}

func TestStrayCodesSortedUnique(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("token=abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keystore.jks"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := AuditServerStraySecrets(dir)
	codes := a.Codes()
	for i := 1; i < len(codes); i++ {
		if codes[i-1] > codes[i] {
			t.Fatalf("not sorted: %v", codes)
		}
	}
}

func TestStrayDescribeStable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("password=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := AuditServerStraySecrets(dir)
	if a.Describe() != a.Describe() {
		t.Fatalf("describe unstable")
	}
	if !strings.Contains(a.Describe(), "env-secret") {
		t.Fatalf("describe=%q", a.Describe())
	}
}

func TestStraySummaryCounts(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.pem"), []byte("-----BEGIN PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := AuditServerStraySecrets(dir)
	if !strings.Contains(a.Summary(), "阻断 1") {
		t.Fatalf("summary=%q", a.Summary())
	}
}
