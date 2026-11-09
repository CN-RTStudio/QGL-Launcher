package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeJMXFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func jmxHasReason(audit JMXAudit, reason string) bool {
	for _, f := range audit.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestJMXCleanServerDirectory(t *testing.T) {
	dir := t.TempDir()
	writeJMXFile(t, dir, "start.sh", "#!/bin/sh\njava -Xmx2G -jar server.jar nogui\n")
	audit := AuditServerJMX(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("unexpected findings: %s", audit.Describe())
	}
	if len(audit.Sources) != 1 {
		t.Fatalf("expected one source, got %v", audit.Sources)
	}
}

func TestJMXMissingDirectoryBlocks(t *testing.T) {
	audit := AuditServerJMX(filepath.Join(t.TempDir(), "absent"))
	if !audit.Blocking() {
		t.Fatal("missing directory must block")
	}
	if !jmxHasReason(audit, jmxReasonMissing) {
		t.Fatal("missing reason not reported")
	}
}

func TestJMXUnauthenticatedRemote(t *testing.T) {
	dir := t.TempDir()
	writeJMXFile(t, dir, "start.sh", "java -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.authenticate=false -jar server.jar\n")
	audit := AuditServerJMX(dir)
	if !audit.Blocking() {
		t.Fatal("unauthenticated JMX must block")
	}
	if !jmxHasReason(audit, jmxReasonUnauthenticated) {
		t.Fatal("unauthenticated reason missing")
	}
}

func TestJMXSSLCliDisabled(t *testing.T) {
	dir := t.TempDir()
	writeJMXFile(t, dir, "run.bat", "java -Dcom.sun.management.jmxremote.ssl=false -jar server.jar\n")
	audit := AuditServerJMX(dir)
	if !jmxHasReason(audit, jmxReasonNoSSL) || !audit.Blocking() {
		t.Fatalf("ssl=false must block: %s", audit.Describe())
	}
}

func TestJMXInlinePassword(t *testing.T) {
	dir := t.TempDir()
	writeJMXFile(t, dir, "start.sh", "java -Dcom.sun.management.jmxremote.password=admin123 -jar server.jar\n")
	audit := AuditServerJMX(dir)
	if !jmxHasReason(audit, jmxReasonInlineSecret) {
		t.Fatal("inline password not flagged")
	}
}

func TestJMXPasswordFileReferenceIsNotInlineSecret(t *testing.T) {
	dir := t.TempDir()
	writeJMXFile(t, dir, "start.sh", "java -Dcom.sun.management.jmxremote.password.file=conf/jmxremote.password -jar server.jar\n")
	writeJMXFile(t, dir, filepath.Join("conf", "jmxremote.password"), "monitor readonly\ncontrol readonly\n")
	audit := AuditServerJMX(dir)
	if jmxHasReason(audit, jmxReasonInlineSecret) {
		t.Fatal("password.file reference misclassified as inline secret")
	}
	if audit.Blocking() {
		t.Fatalf("readable-location password file should not block: %s", audit.Describe())
	}
}

func TestJMXRemotePortBlocks(t *testing.T) {
	dir := t.TempDir()
	writeJMXFile(t, dir, "start.sh", "java -Dcom.sun.management.jmxremote.port=9999 -jar server.jar\n")
	audit := AuditServerJMX(dir)
	if !jmxHasReason(audit, jmxReasonBroadBind) {
		t.Fatal("remote port without loopback binding not flagged")
	}
}

func TestJMXNonLoopbackHostname(t *testing.T) {
	dir := t.TempDir()
	writeJMXFile(t, dir, "start.sh", "java -Djava.rmi.server.hostname=0.0.0.0 -jar server.jar\n")
	audit := AuditServerJMX(dir)
	if !jmxHasReason(audit, jmxReasonBroadBind) {
		t.Fatal("0.0.0.0 rmi host not flagged")
	}
}

func TestJMXLoopbackHostnameAccepted(t *testing.T) {
	dir := t.TempDir()
	writeJMXFile(t, dir, "start.sh", "java -Djava.rmi.server.hostname=127.0.0.1 -jar server.jar\n")
	audit := AuditServerJMX(dir)
	if audit.Blocking() {
		t.Fatalf("loopback host must not block: %s", audit.Describe())
	}
}

func TestJMXManagementPropertiesDisabledAuth(t *testing.T) {
	dir := t.TempDir()
	writeJMXFile(t, dir, filepath.Join("conf", "management.properties"),
		"com.sun.management.jmxremote.authenticate=false\ncom.sun.management.jmxremote.ssl=false\n")
	audit := AuditServerJMX(dir)
	if !jmxHasReason(audit, jmxReasonUnauthenticated) {
		t.Fatal("properties authenticate=false not flagged")
	}
	if !jmxHasReason(audit, jmxReasonNoSSL) {
		t.Fatal("properties ssl=false not flagged")
	}
}
