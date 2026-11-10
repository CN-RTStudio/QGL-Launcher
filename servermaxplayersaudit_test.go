package main

import (
	"testing"
)

func TestMaxPlayersClean(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "max-players=20\nplayer-idle-timeout=5\nrate-limit=3\nview-distance=10\nsimulation-distance=8\n")
	if a := AuditServerMaxPlayers(dir); a.HasWarnings() {
		t.Fatalf("容量配置正常不应报警: %v", a.Describe())
	}
}

func TestMaxPlayersInvalid(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "max-players=abc\n")
	a := AuditServerMaxPlayers(dir)
	if !a.Blocking() || !auditHasReason(a, smpReasonCount) {
		t.Fatalf("非法人数应阻断: %v", a.Describe())
	}
}

func TestMaxPlayersTooHigh(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "max-players=500\n")
	a := AuditServerMaxPlayers(dir)
	if !auditHasReason(a, smpReasonMany) {
		t.Fatalf("过高人数应提示: %v", a.Describe())
	}
}

func TestMaxPlayersIdleDisabled(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "player-idle-timeout=0\n")
	a := AuditServerMaxPlayers(dir)
	if !auditHasReason(a, smpReasonIdle) {
		t.Fatalf("空闲踢出关闭应提示: %v", a.Describe())
	}
}

func TestMaxPlayersRateLimitDisabled(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "rate-limit=0\n")
	a := AuditServerMaxPlayers(dir)
	if !auditHasReason(a, smpReasonRate) {
		t.Fatalf("限流关闭应提示: %v", a.Describe())
	}
}

func TestMaxPlayersViewDistance(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "view-distance=64\nsimulation-distance=2\n")
	a := AuditServerMaxPlayers(dir)
	if !auditHasReason(a, smpReasonView) || !auditHasReason(a, smpReasonSim) {
		t.Fatalf("视距越界应提示: %v", a.Describe())
	}
}
