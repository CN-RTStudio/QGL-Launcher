package main

// instanceguard_test.go —— 实例目录审计内核的测试。
// 注意：符号链接用例在 Windows 上可能因缺少管理员/开发者模式权限而无法创建，
// 遇到该环境限制时用 t.Skip 跳过，不误报失败。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateInstanceRoot(t *testing.T) {
	var lim0 InstanceLimits
	lim := lim0.withDefaults()
	cases := []struct {
		in   string
		want string // 期望错误包含的片段；空表示应通过
	}{
		{"", "empty"},
		{"   ", "empty"},
		{strings.Repeat("a", 5000), "too long"},
		{"bad\x00path", "control characters"},
		{`\\server\share\mc`, "UNC"},
		{"relative/path", "absolute"},
		{".", "normalized"},
		{"./x", "normalized"},
		{`C:\x\..\y`, "normalized"},
	}
	for _, c := range cases {
		_, err := ValidateInstanceRoot(c.in, lim)
		if c.want == "" {
			if err != nil {
				t.Errorf("ValidateInstanceRoot(%q) unexpected error: %v", c.in, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("ValidateInstanceRoot(%q) expected error containing %q, got nil", c.in, c.want)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("ValidateInstanceRoot(%q) error %q does not contain %q", c.in, err.Error(), c.want)
		}
	}
	got, err := ValidateInstanceRoot(`C:\Games\MC`, lim)
	if err != nil || !filepath.IsAbs(got) {
		t.Errorf("valid absolute root rejected: %q err=%v", got, err)
	}
}

func TestAuditInstanceClean(t *testing.T) {
	root := t.TempDir()
	var lim0 InstanceLimits; lim := lim0.withDefaults()
	mkdirAll(t, filepath.Join(root, "versions", "1.19.4"))
	mkdirAll(t, filepath.Join(root, "libraries", "net", "minecraft"))
	writeFile(t, filepath.Join(root, "options.txt"), "renderDistance: 12\n")
	writeFile(t, filepath.Join(root, "versions", "1.19.4", "1.19.4.json"), "{}")

	v := AuditInstance(root, lim)
	if !v.Ok {
		t.Fatalf("clean instance failed: %s", SummarizeInstanceAudit(v))
	}
	if v.EntryCount == 0 {
		t.Fatal("expected entries counted")
	}
}

func TestAuditInstanceEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	var lim0 InstanceLimits; lim := lim0.withDefaults()
	secret := filepath.Join(outside, "secret.txt")
	writeFile(t, secret, "do not touch")
	link := filepath.Join(root, "mods", "evil")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, link); err != nil {
		t.Skip("symlink creation not permitted in this environment: " + err.Error())
	}
	v := AuditInstance(root, lim)
	if v.Ok {
		t.Fatal("escaping symlink must fail audit")
	}
	if len(v.EscapeLinks) != 1 {
		t.Fatalf("expected 1 escape link, got %d: %v", len(v.EscapeLinks), v.EscapeLinks)
	}
	if v.EscapeLinks[0] != "mods/evil" {
		t.Errorf("unexpected escape link path: %s", v.EscapeLinks[0])
	}
}

func TestAuditInstanceCrossVersion(t *testing.T) {
	root := t.TempDir()
	var lim0 InstanceLimits; lim := lim0.withDefaults()
	va := filepath.Join(root, "versions", "1.19.4")
	vb := filepath.Join(root, "versions", "1.20.1")
	mkdirAll(t, va)
	mkdirAll(t, vb)
	writeFile(t, filepath.Join(vb, "1.20.1.json"), "{}")
	link := filepath.Join(va, "cross")
	if err := os.Symlink(filepath.Join(vb, "1.20.1.json"), link); err != nil {
		t.Skip("symlink creation not permitted in this environment: " + err.Error())
	}
	v := AuditInstance(root, lim)
	if v.Ok {
		t.Fatal("cross-version reference must fail audit")
	}
	if len(v.CrossVersionRef) != 1 {
		t.Fatalf("expected 1 cross-version ref, got %v", v.CrossVersionRef)
	}
}

func TestAuditInstanceBadComponents(t *testing.T) {
	root := t.TempDir()
	var lim0 InstanceLimits; lim := lim0.withDefaults()
	bad := filepath.Join(root, "versions", "bad name\x7f")
	mkdirAll(t, bad)
	v := AuditInstance(root, lim)
	if v.Ok {
		t.Fatal("control-char component must fail audit")
	}
	if len(v.BadComponents) == 0 {
		t.Fatal("expected bad component recorded")
	}
}

func TestAuditInstanceOverflow(t *testing.T) {
	root := t.TempDir()
	var lim0 InstanceLimits
	lim := lim0.withDefaults()
	lim.MaxEntries = 5
	// 写入 20 个文件超过 5 条上限
	dir := filepath.Join(root, "mods")
	mkdirAll(t, dir)
	for i := 0; i < 20; i++ {
		writeFile(t, filepath.Join(dir, "m"+string(rune('a'+i%26))+itoa(i)+".jar"), "x")
	}
	v := AuditInstance(root, lim)
	if v.Ok {
		t.Fatal("overflow must fail audit")
	}
	if !strings.Contains(v.Error, "overflow") {
		t.Errorf("expected overflow error, got %q", v.Error)
	}
}

func TestAuditInstanceMissingRoot(t *testing.T) {
	var lim0 InstanceLimits; lim := lim0.withDefaults()
	v := AuditInstance(filepath.Join(t.TempDir(), "nope"), lim)
	if v.Ok {
		t.Fatal("missing root must fail audit")
	}
	if !strings.Contains(v.Error, "not accessible") {
		t.Errorf("expected not accessible error, got %q", v.Error)
	}
}

func TestCheckVersionIsolation(t *testing.T) {
	root := t.TempDir()
	var lim0 InstanceLimits; lim := lim0.withDefaults()
	mkdirAll(t, filepath.Join(root, "versions", "1.19.4"))
	mkdirAll(t, filepath.Join(root, "libraries", "net", "minecraft"))
	v := CheckVersionIsolation(root, lim)
	if !v.Ok {
		t.Fatalf("clean isolation failed: %s", SummarizeInstanceAudit(v))
	}
}

func TestCheckVersionIsolationSymlinkVersion(t *testing.T) {
	root := t.TempDir()
	var lim0 InstanceLimits; lim := lim0.withDefaults()
	real := t.TempDir()
	link := filepath.Join(root, "versions", "1.19.4")
	mkdirAll(t, filepath.Join(root, "libraries"))
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlink creation not permitted in this environment: " + err.Error())
	}
	v := CheckVersionIsolation(root, lim)
	if v.Ok {
		t.Fatal("symlinked version dir must fail isolation")
	}
	if len(v.CrossVersionRef) != 1 {
		t.Fatalf("expected 1 symlink version, got %v", v.CrossVersionRef)
	}
}

func TestSummarizeInstanceAuditText(t *testing.T) {
	root := t.TempDir()
	var lim0 InstanceLimits; lim := lim0.withDefaults()
	mkdirAll(t, filepath.Join(root, "versions", "1.19.4"))
	v := AuditInstance(root, lim)
	s := SummarizeInstanceAudit(v)
	if !strings.Contains(s, "instance audit ok") {
		t.Errorf("unexpected summary: %s", s)
	}
	bad := InstanceVerdict{Ok: false, Root: root, EscapeLinks: []string{"mods/evil"}}
	s2 := SummarizeInstanceAudit(bad)
	if !strings.Contains(s2, "FAILED") || !strings.Contains(s2, "escapeLinks=1") {
		t.Errorf("unexpected failure summary: %s", s2)
	}
}

func TestItoa(t *testing.T) {
	cases := []struct{ in int; want string }{
		{0, "0"}, {1, "1"}, {9, "9"}, {10, "10"}, {12345, "12345"}, {1088, "1088"},
	}
	for _, c := range cases {
		if got := itoa(c.in); got != c.want {
			t.Errorf("itoa(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func mkdirAll(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
