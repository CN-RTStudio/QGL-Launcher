package main

import (
	"os"
	"path/filepath"
	"testing"
)

func smaWrite(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func smaReasons(a *MovementGuardAudit) map[string]bool {
	out := map[string]bool{}
	for _, f := range a.Findings {
		out[f.Reason] = true
	}
	return out
}

func TestAuditServerMovementGuardsMissingDir(t *testing.T) {
	a := AuditServerMovementGuards(filepath.Join(t.TempDir(), "absent"))
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !smaReasons(a)[smaReasonMissing] {
		t.Fatalf("expected missing: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsClean(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "allow-flight=false\nplayer-idle-timeout=15\nspawn-protection=16\nmax-world-size=29999984\nmax-players=20\ndebug=false\n")
	a := AuditServerMovementGuards(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if a.HasWarnings() {
		t.Fatalf("unexpected warnings: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsFlight(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "allow-flight=true\n")
	a := AuditServerMovementGuards(dir)
	if !smaReasons(a)[smaReasonFlight] {
		t.Fatalf("expected flight finding: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsIdleZero(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "player-idle-timeout=0\n")
	a := AuditServerMovementGuards(dir)
	if !smaReasons(a)[smaReasonIdle] {
		t.Fatalf("expected idle finding: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsIdleSmall(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "player-idle-timeout=2\n")
	a := AuditServerMovementGuards(dir)
	if !smaReasons(a)[smaReasonIdle] {
		t.Fatalf("expected idle finding: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsSpawnProtectionZero(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "spawn-protection=0\n")
	a := AuditServerMovementGuards(dir)
	if !smaReasons(a)[smaReasonSpawnProt] {
		t.Fatalf("expected spawn protection finding: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsSpawnProtectionNegative(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "spawn-protection=-8\n")
	a := AuditServerMovementGuards(dir)
	if !smaReasons(a)[smaReasonBadValue] {
		t.Fatalf("expected bad-value: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsWorldSizeTooLarge(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "max-world-size=99999999\n")
	a := AuditServerMovementGuards(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !smaReasons(a)[smaReasonWorldSize] {
		t.Fatalf("expected world size finding: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsWorldSizeInvalid(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "max-world-size=0\n")
	a := AuditServerMovementGuards(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsPlayerCap(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "max-players=1000\n")
	a := AuditServerMovementGuards(dir)
	if !smaReasons(a)[smaReasonPlayerCap] {
		t.Fatalf("expected player cap finding: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsDebug(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "debug=true\n")
	a := AuditServerMovementGuards(dir)
	if !smaReasons(a)[smaReasonDebug] {
		t.Fatalf("expected debug finding: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsPaperJoinLimit(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "allow-flight=false\n")
	smaWrite(t, dir, "config/paper-global.yml", "misc:\n  max-joins-per-tick: 0\n")
	a := AuditServerMovementGuards(dir)
	if !smaReasons(a)[smaReasonBadValue] {
		t.Fatalf("expected bad-value: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsPaperCollisions(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "allow-flight=false\n")
	smaWrite(t, dir, "config/paper-global.yml", "collisions:\n  enable-player-collisions: true\n")
	a := AuditServerMovementGuards(dir)
	if !smaReasons(a)[smaReasonFlight] {
		t.Fatalf("expected collisions finding: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsSymlinkRoot(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerMovementGuards(link)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsBadIntegers(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "player-idle-timeout=abc\nspawn-protection=xyz\nmax-players=many\n")
	a := AuditServerMovementGuards(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !smaReasons(a)[smaReasonBadValue] {
		t.Fatalf("expected bad-value: %s", a.Describe())
	}
}

func TestAuditServerMovementGuardsDescribe(t *testing.T) {
	dir := t.TempDir()
	smaWrite(t, dir, "server.properties", "allow-flight=true\nplayer-idle-timeout=0\nspawn-protection=0\ndebug=true\n")
	a := AuditServerMovementGuards(dir)
	if a.Describe() == "" {
		t.Fatalf("expected description")
	}
	if !a.HasWarnings() {
		t.Fatalf("expected warnings: %s", a.Describe())
	}
}
