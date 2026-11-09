package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)


func packCodes(audit *ServerResourcePackAudit, reason string) bool {
	for _, code := range audit.Codes() {
		if code == reason {
			return true
		}
	}
	return false
}

func TestAuditResourcePackNoPack(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "online-mode=true\nserver-port=25565\n")
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.PackURL != "" || audit.Blocking() || len(audit.Findings) != 0 {
		t.Fatalf("no pack should be clean: %s", audit.Describe())
	}
	if audit.Summary() != "未配置资源包" {
		t.Fatalf("unexpected summary: %s", audit.Summary())
	}
}

func TestAuditResourcePackHTTPSWithHash(t *testing.T) {
	dir := t.TempDir()
	hash := strings.Repeat("ab", 20)
	writeBindingProperties(t, dir, "resource-pack=https://cdn.test/pack.zip\nresource-pack-sha1="+hash+"\n")
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Blocking() || len(audit.Findings) != 0 {
		t.Fatalf("https + valid hash should pass: %s", audit.Describe())
	}
	if !strings.HasPrefix(audit.Summary(), "资源包下载策略校验通过") {
		t.Fatalf("unexpected summary: %s", audit.Summary())
	}
}

func TestAuditResourcePackHTTPWarns(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "resource-pack=http://cdn.test/pack.zip\nresource-pack-sha1="+strings.Repeat("ab", 20)+"\n")
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !packCodes(audit, packReasonInsecure) {
		t.Fatalf("http pack should warn: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatal("http pack must not block startup")
	}
}

func TestAuditResourcePackMissingHashWarns(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "resource-pack=https://cdn.test/pack.zip\n")
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !packCodes(audit, packReasonMissingHash) {
		t.Fatalf("missing hash should warn: %s", audit.Describe())
	}
}

func TestAuditResourcePackBadHashBlocks(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "resource-pack=https://cdn.test/pack.zip\nresource-pack-sha1=xyz\n")
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !packCodes(audit, packReasonBadHash) {
		t.Fatalf("bad hash must block: %s", audit.Describe())
	}
}

func TestAuditResourcePackPlaceholderHashBlocks(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "resource-pack=https://cdn.test/pack.zip\nresource-pack-sha1="+strings.Repeat("0", 40)+"\n")
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !packCodes(audit, packReasonPlaceholder) {
		t.Fatalf("all-zero hash must block: %s", audit.Describe())
	}
}

func TestAuditResourcePackUserinfoBlocks(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "resource-pack=https://user:pass@cdn.test/pack.zip\nresource-pack-sha1="+strings.Repeat("ab", 20)+"\n")
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !packCodes(audit, packReasonUserinfo) {
		t.Fatalf("embedded credentials must block: %s", audit.Describe())
	}
}

func TestAuditResourcePackBadSchemeBlocks(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "resource-pack=file:///etc/passwd\n")
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !packCodes(audit, packReasonBadScheme) {
		t.Fatalf("file scheme must block: %s", audit.Describe())
	}
}

func TestAuditResourcePackControlBytesBlock(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "resource-pack=https://cdn.test/pa\x01ck.zip\n")
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !packCodes(audit, packReasonBadScheme) {
		t.Fatalf("control bytes in URL must block: %s", audit.Describe())
	}
}

func TestAuditResourcePackBadPromptWarns(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "resource-pack=https://cdn.test/pack.zip\nresource-pack-prompt="+strings.Repeat("提", 300)+"\n")
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !packCodes(audit, packReasonBadPrompt) {
		t.Fatalf("long prompt should warn: %s", audit.Describe())
	}
}

func TestAuditResourcePackDuplicateKeysWarn(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "resource-pack=https://a.test/x\nresource-pack=https://b.test/y\nresource-pack-sha1="+strings.Repeat("ab", 20)+"\n")
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !packCodes(audit, packReasonDuplicateKey) {
		t.Fatalf("duplicate keys should warn: %s", audit.Describe())
	}
}

func TestAuditResourcePackSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.properties")
	if err := os.WriteFile(real, []byte("resource-pack=https://cdn.test/x\n"), 0o600); err != nil {
		t.Fatalf("write real: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "server.properties")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !packCodes(audit, packReasonSymlink) {
		t.Fatalf("symlink must block: %s", audit.Describe())
	}
}

func TestAuditResourcePackMissingFile(t *testing.T) {
	dir := t.TempDir()
	audit, err := AuditServerResourcePack(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Present || !packCodes(audit, packReasonMissing) {
		t.Fatalf("missing properties should be reported: %+v", audit)
	}
}
