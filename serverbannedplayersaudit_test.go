package main

import (
	"os"
	"path/filepath"
	"testing"
)

func sbpWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "banned-players.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func sbpHas(findings []BannedPlayerFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestBannedPlayersClean(t *testing.T) {
	dir := t.TempDir()
	sbpWrite(t, dir, `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aafe","name":"Notch","created":"2024-01-02T03:04:05Z","source":"Server","expires":"2025-01-02T03:04:05Z","reason":"cheating"}]`)
	if a := AuditServerBannedPlayers(dir); a.HasWarnings() {
		t.Fatalf("合法封禁名单不应报警: %v", a.Describe())
	}
}

func TestBannedPlayersBadJSON(t *testing.T) {
	dir := t.TempDir()
	sbpWrite(t, dir, `[{"uuid":`)
	a := AuditServerBannedPlayers(dir)
	if !a.Blocking() || !sbpHas(a.Findings, sbpReasonShape) {
		t.Fatalf("非法 JSON 应阻断: %v", a.Describe())
	}
}

func TestBannedPlayersDuplicate(t *testing.T) {
	dir := t.TempDir()
	sbpWrite(t, dir, `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aafe","name":"A"},{"uuid":"069A79F4-44E9-4726-A5BE-FCA90E38AAFE","name":"B"}]`)
	a := AuditServerBannedPlayers(dir)
	if !a.Blocking() || !sbpHas(a.Findings, sbpReasonDup) {
		t.Fatalf("重复 uuid 应阻断: %v", a.Describe())
	}
}

func TestBannedPlayersBadName(t *testing.T) {
	dir := t.TempDir()
	sbpWrite(t, dir, `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aafe","name":"bad name!"}]`)
	a := AuditServerBannedPlayers(dir)
	if !sbpHas(a.Findings, sbpReasonName) {
		t.Fatalf("非法玩家名应报警: %v", a.Describe())
	}
}

func TestBannedPlayersSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(t.TempDir(), "bans.json")
	if err := os.WriteFile(real, []byte("[]"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "banned-players.json")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerBannedPlayers(dir)
	if !sbpHas(a.Findings, sbpReasonLink) {
		t.Fatalf("符号链接应报警: %v", a.Describe())
	}
}
