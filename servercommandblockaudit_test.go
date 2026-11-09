package main

import (
	"os"
	"path/filepath"
	"testing"
)

func scbWrite(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func scbReasons(a *CommandBlockAudit) map[string]bool {
	out := map[string]bool{}
	for _, f := range a.Findings {
		out[f.Reason] = true
	}
	return out
}

func TestAuditServerCommandBlocksMissingDir(t *testing.T) {
	a := AuditServerCommandBlocks(filepath.Join(t.TempDir(), "absent"))
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !scbReasons(a)[scbReasonMissing] {
		t.Fatalf("expected missing reason: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksEmptyDirNoFindings(t *testing.T) {
	a := AuditServerCommandBlocks(t.TempDir())
	if len(a.Findings) != 0 {
		t.Fatalf("expected no findings: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksCleanDefaults(t *testing.T) {
	dir := t.TempDir()
	scbWrite(t, dir, "server.properties", "enable-command-block=false\nop-permission-level=2\nfunction-permission-level=2\nmaxCommandChainLength=65536\nmaxCommandForkCount=16\n")
	a := AuditServerCommandBlocks(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !scbReasons(a)[scbReasonNoBlock] {
		t.Fatalf("expected disabled notice: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksChainHardLimit(t *testing.T) {
	dir := t.TempDir()
	scbWrite(t, dir, "server.properties", "maxCommandChainLength=999999\n")
	a := AuditServerCommandBlocks(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !scbReasons(a)[scbReasonChainLong] {
		t.Fatalf("expected chain reason: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksChainSoftLimit(t *testing.T) {
	dir := t.TempDir()
	scbWrite(t, dir, "server.properties", "maxCommandChainLength=131072\n")
	a := AuditServerCommandBlocks(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !a.HasWarnings() {
		t.Fatalf("expected warning: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksForkZero(t *testing.T) {
	dir := t.TempDir()
	scbWrite(t, dir, "server.properties", "maxCommandForkCount=0\n")
	a := AuditServerCommandBlocks(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksRCECombo(t *testing.T) {
	dir := t.TempDir()
	scbWrite(t, dir, "server.properties", "enable-command-block=true\nfunction-permission-level=4\n")
	a := AuditServerCommandBlocks(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !scbReasons(a)[scbReasonRCECombo] {
		t.Fatalf("expected combo reason: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksOpCombo(t *testing.T) {
	dir := t.TempDir()
	scbWrite(t, dir, "server.properties", "enable-command-block=true\nop-permission-level=4\n")
	a := AuditServerCommandBlocks(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !scbReasons(a)[scbReasonOpHigh] {
		t.Fatalf("expected op reason: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksOutOfRangeLevels(t *testing.T) {
	dir := t.TempDir()
	scbWrite(t, dir, "server.properties", "op-permission-level=9\nfunction-permission-level=0\n")
	a := AuditServerCommandBlocks(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !scbReasons(a)[scbReasonBadValue] {
		t.Fatalf("expected bad-value: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksSilentConsole(t *testing.T) {
	dir := t.TempDir()
	scbWrite(t, dir, "server.properties", "enable-command-block=false\n")
	scbWrite(t, dir, "spigot.yml", "commands:\n  silent-commandblock-console: true\n  spam-exclusions:\n")
	a := AuditServerCommandBlocks(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !scbReasons(a)[scbReasonSilent] {
		t.Fatalf("expected silent reason: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksSpamExclusions(t *testing.T) {
	dir := t.TempDir()
	scbWrite(t, dir, "server.properties", "enable-command-block=false\n")
	scbWrite(t, dir, "spigot.yml", "commands:\n  spam-exclusions:\n    - \"/*\"\n    - /me\n")
	a := AuditServerCommandBlocks(dir)
	if !scbReasons(a)[scbReasonSpamList] {
		t.Fatalf("expected spam list reason: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksPaperOutput(t *testing.T) {
	dir := t.TempDir()
	scbWrite(t, dir, "server.properties", "enable-command-block=false\n")
	scbWrite(t, dir, "config/paper-world-defaults.yml", "environment:\n  command-block-output: true\n")
	a := AuditServerCommandBlocks(dir)
	if !scbReasons(a)[scbReasonSilent] {
		t.Fatalf("expected output warning: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksSymlinkRoot(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerCommandBlocks(link)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !scbReasons(a)[scbReasonSymlink] {
		t.Fatalf("expected symlink reason: %s", a.Describe())
	}
}

func TestAuditServerCommandBlocksDescribeOrdering(t *testing.T) {
	dir := t.TempDir()
	scbWrite(t, dir, "server.properties", "enable-command-block=true\nfunction-permission-level=4\nop-permission-level=4\nmaxCommandChainLength=0\n")
	a := AuditServerCommandBlocks(dir)
	desc := a.Describe()
	if desc == "" {
		t.Fatalf("expected description")
	}
	if !a.HasWarnings() && !a.Blocking() {
		t.Fatalf("expected at least one finding")
	}
}
