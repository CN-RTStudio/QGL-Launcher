package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRconProperties(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o600); err != nil {
		t.Fatalf("write properties: %v", err)
	}
}

func rconHas(audit *ServerRconAudit, reason string) bool {
	for _, code := range audit.Codes() {
		if code == reason {
			return true
		}
	}
	return false
}

func TestAuditServerRconDisabledClean(t *testing.T) {
	dir := t.TempDir()
	writeRconProperties(t, dir, "enable-rcon=false\nserver-port=25565\n")
	audit, err := AuditServerRcon(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Blocking() || len(audit.Findings) != 0 {
		t.Fatalf("disabled rcon should be clean: %s", audit.Describe())
	}
	if audit.Summary() != "RCON/Query 暴露面校验通过" {
		t.Fatalf("unexpected summary: %s", audit.Summary())
	}
}

func TestAuditServerRconMissingFile(t *testing.T) {
	dir := t.TempDir()
	audit, err := AuditServerRcon(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Present || !rconHas(audit, rconReasonMissing) {
		t.Fatalf("missing file should be reported: %+v", audit)
	}
	if audit.Blocking() {
		t.Fatal("missing properties must not block")
	}
}

func TestAuditServerRconEmptyPasswordBlocks(t *testing.T) {
	dir := t.TempDir()
	writeRconProperties(t, dir, "enable-rcon=true\nrcon.password=\nrcon.port=25575\nserver-port=25565\n")
	audit, err := AuditServerRcon(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !rconHas(audit, rconReasonEmptyPassword) {
		t.Fatalf("empty rcon password must block: %s", audit.Describe())
	}
}

func TestAuditServerRconWeakPasswordWarns(t *testing.T) {
	dir := t.TempDir()
	writeRconProperties(t, dir, "enable-rcon=true\nrcon.password=1234\n")
	audit, err := AuditServerRcon(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !rconHas(audit, rconReasonWeakPassword) {
		t.Fatalf("short password should warn: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatal("weak password must not block")
	}
}

func TestAuditServerRconBadPasswordBlocks(t *testing.T) {
	dir := t.TempDir()
	writeRconProperties(t, dir, "enable-rcon=true\nrcon.password=has space pass\n")
	audit, err := AuditServerRcon(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !rconHas(audit, rconReasonBadPassword) {
		t.Fatalf("password with whitespace must block: %s", audit.Describe())
	}
}

func TestAuditServerRconPortCollision(t *testing.T) {
	dir := t.TempDir()
	writeRconProperties(t, dir, "enable-rcon=true\nrcon.password=longenough\nrcon.port=25565\nserver-port=25565\n")
	audit, err := AuditServerRcon(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !rconHas(audit, rconReasonPortCollision) {
		t.Fatalf("port collision should warn: %s", audit.Describe())
	}
}

func TestAuditServerRconBadPortBlocks(t *testing.T) {
	dir := t.TempDir()
	writeRconProperties(t, dir, "enable-rcon=true\nrcon.password=longenough\nrcon.port=70000\n")
	audit, err := AuditServerRcon(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !rconHas(audit, rconReasonBadPort) {
		t.Fatalf("out-of-range port must block: %s", audit.Describe())
	}
}

func TestAuditServerRconBroadcastWarns(t *testing.T) {
	dir := t.TempDir()
	writeRconProperties(t, dir, "enable-rcon=true\nrcon.password=longenough\nbroadcast-rcon-to-ops=true\n")
	audit, err := AuditServerRcon(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !rconHas(audit, rconReasonBroadcast) {
		t.Fatalf("broadcast should warn: %s", audit.Describe())
	}
}

func TestAuditServerRconStalePasswordWarns(t *testing.T) {
	dir := t.TempDir()
	writeRconProperties(t, dir, "enable-rcon=false\nrcon.password=keptsecret\n")
	audit, err := AuditServerRcon(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !rconHas(audit, rconReasonStalePassword) {
		t.Fatalf("stale password should warn: %s", audit.Describe())
	}
}

func TestAuditServerQueryEnabledWarns(t *testing.T) {
	dir := t.TempDir()
	writeRconProperties(t, dir, "enable-query=true\nserver-ip=0.0.0.0\nquery.port=25565\nserver-port=25565\n")
	audit, err := AuditServerRcon(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	for _, want := range []string{rconReasonQueryEnabled, rconReasonQueryPublic, rconReasonQueryCollision} {
		if !rconHas(audit, want) {
			t.Fatalf("missing %s in %s", want, audit.Describe())
		}
	}
}

func TestAuditServerDuplicateKeysWarn(t *testing.T) {
	dir := t.TempDir()
	writeRconProperties(t, dir, "enable-rcon=true\nrcon.password=longenough\nrcon.password=otherpass\n")
	audit, err := AuditServerRcon(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !rconHas(audit, rconReasonDuplicateKey) {
		t.Fatalf("duplicate keys should warn: %s", audit.Describe())
	}
}

func TestAuditServerRconSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.properties")
	if err := os.WriteFile(real, []byte("enable-rcon=true\n"), 0o600); err != nil {
		t.Fatalf("write real: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "server.properties")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	audit, err := AuditServerRcon(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !rconHas(audit, rconReasonSymlink) {
		t.Fatalf("symlink must block: %s", audit.Describe())
	}
}

func TestRconDescribeKeepsValues(t *testing.T) {
	audit := &ServerRconAudit{Findings: []RconFinding{
		{Key: "rcon.port", Value: "70000", Reason: rconReasonBadPort, Detail: "x", Blocking: true},
	}}
	if !strings.Contains(audit.Describe(), "70000") {
		t.Fatalf("describe should include value: %s", audit.Describe())
	}
	if len(audit.Codes()) != 1 {
		t.Fatalf("codes should contain one entry: %v", audit.Codes())
	}
}
