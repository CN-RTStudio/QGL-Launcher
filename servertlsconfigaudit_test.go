package main

import (
	"os"
	"path/filepath"
	"testing"
)

func tlsWrite(t *testing.T, dir, rel, body string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), perm); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func tlsHasReason(audit TLSAudit, reason string) bool {
	for _, f := range audit.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestTLSMissingDirectoryBlocks(t *testing.T) {
	audit := AuditServerTLS(filepath.Join(t.TempDir(), "absent"))
	if !audit.Blocking() {
		t.Fatal("missing server directory must block")
	}
	if !tlsHasReason(audit, tlsReasonMissing) {
		t.Fatal("missing reason not reported")
	}
}

func TestTLSCleanConfigPasses(t *testing.T) {
	dir := t.TempDir()
	tlsWrite(t, dir, "server.properties", "online-mode=true\n", 0o600)
	audit := AuditServerTLS(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("unexpected findings: %s", audit.Describe())
	}
}

func TestTLSWeakProtocolBlocks(t *testing.T) {
	dir := t.TempDir()
	tlsWrite(t, dir, "config/tls.properties", "enabled-protocols=TLSv1,TLSv1.1,TLSv1.2\n", 0o600)
	audit := AuditServerTLS(dir)
	if !audit.Blocking() {
		t.Fatal("weak protocol must block")
	}
	if !tlsHasReason(audit, tlsReasonWeakProtocol) {
		t.Fatal("weak protocol reason not reported")
	}
}

func TestTLSWeakCipherBlocks(t *testing.T) {
	dir := t.TempDir()
	tlsWrite(t, dir, "config/ssl.properties", "cipher-suites=TLS_RSA_WITH_RC4_128_SHA\n", 0o600)
	audit := AuditServerTLS(dir)
	if !tlsHasReason(audit, tlsReasonWeakCipher) {
		t.Fatal("weak cipher not reported")
	}
}

func TestTLSPlaintextKeystorePasswordBlocks(t *testing.T) {
	dir := t.TempDir()
	tlsWrite(t, dir, "config/tls.properties", "keystore.password=hunter2\n", 0o600)
	audit := AuditServerTLS(dir)
	if !tlsHasReason(audit, tlsReasonPlaintextPass) {
		t.Fatal("plaintext keystore password not reported")
	}
}

func TestTLSKeystoreOutsideDirBlocks(t *testing.T) {
	dir := t.TempDir()
	parent := t.TempDir()
	tlsWrite(t, parent, "evil.p12", "x", 0o600)
	rel := filepath.Join("..", filepath.Base(parent), "evil.p12")
	tlsWrite(t, dir, "config/tls.properties", "keystore.path="+rel+"\n", 0o600)
	audit := AuditServerTLS(dir)
	if !tlsHasReason(audit, tlsReasonBadKeystore) {
		t.Fatal("path traversal keystore not reported")
	}
}

func TestTLSMissingKeystoreBlocks(t *testing.T) {
	dir := t.TempDir()
	tlsWrite(t, dir, "config/tls.properties", "keystore.path=config/absent.jks\n", 0o600)
	audit := AuditServerTLS(dir)
	if !tlsHasReason(audit, tlsReasonMissingKeystore) {
		t.Fatal("missing keystore not reported")
	}
}

func TestTLSWorldReadableKeystoreBlocks(t *testing.T) {
	dir := t.TempDir()
	tlsWrite(t, dir, "keystore.jks", "x", 0o644)
	tlsWrite(t, dir, "config/tls.properties", "keystore.path=keystore.jks\n", 0o600)
	audit := AuditServerTLS(dir)
	if !tlsHasReason(audit, tlsReasonWorldReadable) {
		t.Fatal("world readable keystore not reported")
	}
}

func TestTLSSymlinkKeystoreBlocks(t *testing.T) {
	dir := t.TempDir()
	target := tlsWrite(t, dir, "real.jks", "x", 0o600)
	if err := os.Symlink(target, filepath.Join(dir, "link.jks")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	tlsWrite(t, dir, "config/tls.properties", "keystore.path=link.jks\n", 0o600)
	audit := AuditServerTLS(dir)
	if !tlsHasReason(audit, tlsReasonSymlink) {
		t.Fatal("symlink keystore not reported")
	}
}

func TestTLSEnabledWithoutKeystoreBlocks(t *testing.T) {
	dir := t.TempDir()
	tlsWrite(t, dir, "config/tls.properties", "ssl-enabled=true\n", 0o600)
	audit := AuditServerTLS(dir)
	if !tlsHasReason(audit, tlsReasonMissingKeystore) {
		t.Fatal("TLS without keystore not reported")
	}
}

func TestTLSDescribeSkipsOK(t *testing.T) {
	audit := TLSAudit{}
	audit.add("", tlsReasonOK, "fine", false)
	if audit.Describe() != "TLS 配置未发现风险" {
		t.Fatalf("unexpected describe: %s", audit.Describe())
	}
}

func TestTLSNoConfigPasses(t *testing.T) {
	audit := AuditServerTLS(t.TempDir())
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("unexpected findings: %s", audit.Describe())
	}
}
