package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestJMXManagementPropertiesPort(t *testing.T) {
	dir := t.TempDir()
	writeJMXFile(t, dir, filepath.Join("config", "management.properties"),
		"com.sun.management.jmxremote.port=7091\n")
	audit := AuditServerJMX(dir)
	if !jmxHasReason(audit, jmxReasonBroadBind) {
		t.Fatal("properties port not flagged")
	}
}

func TestJMXManagementPropertiesCommentsIgnored(t *testing.T) {
	dir := t.TempDir()
	writeJMXFile(t, dir, "management.properties", "# com.sun.management.jmxremote.authenticate=false\n! ssl=false\n")
	audit := AuditServerJMX(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("comments must be ignored: %s", audit.Describe())
	}
}

func TestJMXPasswordFileMissing(t *testing.T) {
	dir := t.TempDir()
	writeJMXFile(t, dir, "management.properties", "com.sun.management.jmxremote.password.file=conf/missing.password\n")
	audit := AuditServerJMX(dir)
	if !jmxHasReason(audit, jmxReasonMissing) {
		t.Fatal("missing password file not reported")
	}
}

func TestJMXPasswordFileWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix permission semantics")
	}
	dir := t.TempDir()
	secret := writeJMXFile(t, dir, filepath.Join("conf", "jmxremote.password"), "monitor s3cret\n")
	if err := os.Chmod(secret, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	writeJMXFile(t, dir, "management.properties", "com.sun.management.jmxremote.password.file=conf/jmxremote.password\n")
	audit := AuditServerJMX(dir)
	if !jmxHasReason(audit, jmxReasonPasswordReadable) {
		t.Fatal("world readable password file not reported")
	}
	if audit.Blocking() {
		t.Fatal("world readable secret should stay a warning")
	}
}

func TestJMXPasswordFileSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	target := writeJMXFile(t, dir, "elsewhere.secret", "monitor s3cret\n")
	link := filepath.Join(dir, "conf", "jmxremote.password")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	writeJMXFile(t, dir, "management.properties", "com.sun.management.jmxremote.password.file=conf/jmxremote.password\n")
	audit := AuditServerJMX(dir)
	if !jmxHasReason(audit, jmxReasonSymlink) || !audit.Blocking() {
		t.Fatalf("symlinked password file must block: %s", audit.Describe())
	}
}

func TestJMXSymlinkedScriptBlocks(t *testing.T) {
	dir := t.TempDir()
	target := writeJMXFile(t, dir, "real.sh", "java -jar server.jar\n")
	link := filepath.Join(dir, "start.sh")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	audit := AuditServerJMX(dir)
	if !audit.Blocking() || !jmxHasReason(audit, jmxReasonSymlink) {
		t.Fatalf("symlinked startup script must block: %s", audit.Describe())
	}
}

func TestJMXOversizedScriptBlocks(t *testing.T) {
	dir := t.TempDir()
	body := strings.Repeat("a", jmxMaxFileBytes+1)
	writeJMXFile(t, dir, "start.sh", body)
	audit := AuditServerJMX(dir)
	if !jmxHasReason(audit, jmxReasonTooLarge) || !audit.Blocking() {
		t.Fatalf("oversized script must block: %s", audit.Describe())
	}
}

func TestJMXSummaryAndCodes(t *testing.T) {
	audit := JMXAudit{Dir: "x"}
	audit.add("start.sh", jmxReasonUnauthenticated, "no auth", true)
	audit.add("management.properties", jmxReasonPasswordReadable, "readable", false)
	codes := audit.Codes()
	if len(codes) != 2 || codes[0] != jmxReasonPasswordReadable || codes[1] != jmxReasonUnauthenticated {
		t.Fatalf("codes not sorted: %v", codes)
	}
	if !strings.Contains(audit.Summary(), "blocking=1") || !strings.Contains(audit.Summary(), "warnings=1") {
		t.Fatalf("summary wrong: %s", audit.Summary())
	}
}
