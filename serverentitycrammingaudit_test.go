package main

import (
	"os"
	"path/filepath"
	"testing"
)

func secWrite(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func secReasons(a *EntityCrammingAudit) map[string]bool {
	out := map[string]bool{}
	for _, f := range a.Findings {
		out[f.Reason] = true
	}
	return out
}

func TestAuditServerEntityCrammingMissingDir(t *testing.T) {
	a := AuditServerEntityCramming(filepath.Join(t.TempDir(), "absent"))
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !secReasons(a)[secReasonMissing] {
		t.Fatalf("expected missing: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingClean(t *testing.T) {
	dir := t.TempDir()
	secWrite(t, dir, "spigot.yml", "world-settings:\n  default:\n    max-entity-collisions: 8\n    nerf-spawner-mobs: true\n    mob-spawn-range: 8\n")
	a := AuditServerEntityCramming(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingCollisionsZero(t *testing.T) {
	dir := t.TempDir()
	secWrite(t, dir, "spigot.yml", "world-settings:\n  default:\n    max-entity-collisions: 0\n")
	a := AuditServerEntityCramming(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !secReasons(a)[secReasonCramming] {
		t.Fatalf("expected cramming finding: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingCollisionsHigh(t *testing.T) {
	dir := t.TempDir()
	secWrite(t, dir, "spigot.yml", "world-settings:\n  default:\n    max-entity-collisions: 64\n")
	a := AuditServerEntityCramming(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !secReasons(a)[secReasonCramming] {
		t.Fatalf("expected cramming warning: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingSpawnerNerf(t *testing.T) {
	dir := t.TempDir()
	secWrite(t, dir, "spigot.yml", "world-settings:\n  default:\n    nerf-spawner-mobs: false\n")
	a := AuditServerEntityCramming(dir)
	if !secReasons(a)[secReasonSpawner] {
		t.Fatalf("expected spawner finding: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingActivationRange(t *testing.T) {
	dir := t.TempDir()
	secWrite(t, dir, "spigot.yml", "world-settings:\n  default:\n    entity-activation-range:\n      animals: 96\n      monsters: 32\n      misc: 16\n")
	a := AuditServerEntityCramming(dir)
	if !secReasons(a)[secReasonActivation] {
		t.Fatalf("expected activation finding: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingSpawnRange(t *testing.T) {
	dir := t.TempDir()
	secWrite(t, dir, "spigot.yml", "world-settings:\n  default:\n    mob-spawn-range: 16\n")
	a := AuditServerEntityCramming(dir)
	if !secReasons(a)[secReasonSpawnRange] {
		t.Fatalf("expected spawn range finding: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingSpawnRangeZero(t *testing.T) {
	dir := t.TempDir()
	secWrite(t, dir, "spigot.yml", "world-settings:\n  default:\n    mob-spawn-range: 0\n")
	a := AuditServerEntityCramming(dir)
	if !secReasons(a)[secReasonBadValue] {
		t.Fatalf("expected bad value: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingSaveLimitUnbounded(t *testing.T) {
	dir := t.TempDir()
	secWrite(t, dir, "spigot.yml", "world-settings:\n  default:\n    entity-per-chunk-save-limit:\n      arrow: -1\n      experience_orb: 32\n")
	a := AuditServerEntityCramming(dir)
	if !secReasons(a)[secReasonSaveLimit] {
		t.Fatalf("expected save limit finding: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingPaperLimit(t *testing.T) {
	dir := t.TempDir()
	secWrite(t, dir, "config/paper-global.yml", "chunks:\n  entity-per-chunk-save-limit:\n    arrow: -1\n    ender_pearl: -1\n")
	a := AuditServerEntityCramming(dir)
	if !secReasons(a)[secReasonPaperLimit] {
		t.Fatalf("expected paper limit finding: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingBadValue(t *testing.T) {
	dir := t.TempDir()
	secWrite(t, dir, "spigot.yml", "world-settings:\n  default:\n    max-entity-collisions: many\n    nerf-spawner-mobs: maybe\n")
	a := AuditServerEntityCramming(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !secReasons(a)[secReasonBadValue] {
		t.Fatalf("expected bad-value: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingPerWorldOverride(t *testing.T) {
	dir := t.TempDir()
	secWrite(t, dir, "spigot.yml", "world-settings:\n  default:\n    max-entity-collisions: 8\n  world_nether:\n    max-entity-collisions: 128\n")
	a := AuditServerEntityCramming(dir)
	if !secReasons(a)[secReasonCramming] {
		t.Fatalf("expected per-world finding: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingSymlinkRoot(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerEntityCramming(link)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
}

func TestAuditServerEntityCrammingEmptyDir(t *testing.T) {
	a := AuditServerEntityCramming(t.TempDir())
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !secReasons(a)[secReasonOK] {
		t.Fatalf("expected ok notice: %s", a.Describe())
	}
}
