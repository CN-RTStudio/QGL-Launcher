package main

import (
	"path/filepath"
	"testing"
)

func gameRoots(t *testing.T) (root, libs, versions string) {
	root = filepath.Join(t.TempDir(), ".minecraft")
	libs = filepath.Join(root, "libraries")
	versions = filepath.Join(root, "versions", "1.20")
	return root, libs, versions
}

func TestAuditGameClasspathAcceptsNormal(t *testing.T) {
	root, libs, versions := gameRoots(t)
	entries := []string{
		filepath.Join(libs, "com", "mojang", "a.jar"),
		filepath.Join(libs, "org", "lwjgl", "lwjgl.jar"),
		filepath.Join(versions, "1.20.jar"),
	}
	g := AuditGameClasspath(entries, []string{root})
	if g.HasCritical() {
		t.Fatalf("正常整合包 classpath 应放行，首个 code=%s", g.FirstCriticalCode())
	}
	if len(g.SafeEntries) != 3 {
		t.Fatalf("安全条目数应为 3，得到 %d", len(g.SafeEntries))
	}
}

func TestAuditGameClasspathDeduplicates(t *testing.T) {
	root, libs, _ := gameRoots(t)
	jar := filepath.Join(libs, "a.jar")
	g := AuditGameClasspath([]string{jar, jar, jar}, []string{root})
	if len(g.SafeEntries) != 1 {
		t.Fatalf("重复条目应去重为 1，得到 %d", len(g.SafeEntries))
	}
	if !gameAuditHasWarn(g, "gcp-duplicate") {
		t.Fatal("应记录 gcp-duplicate warn")
	}
}

func TestAuditGameClasspathRejectsBadEntries(t *testing.T) {
	root, libs, versions := gameRoots(t)
	inside := filepath.Join(libs, "ok.jar")
	cases := []struct {
		name  string
		entry string
		code  string
	}{
		{"empty", "", "gcp-empty"},
		{"unc", `\\host\share\x.jar`, "gcp-unc"},
		{"relative", "libraries/a.jar", "gcp-not-absolute"},
		{"traversal", filepath.Join(versions, "..", "..", "evil.jar"), "gcp-traversal"},
		{"not-jar", filepath.Join(libs, "lib.txt"), "gcp-not-jar"},
		{"outside", filepath.Join(t.TempDir(), "evil.jar"), "gcp-outside-root"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := AuditGameClasspath([]string{inside, c.entry}, []string{root})
			if !gameFindingsHasCode(g.Findings, c.code) {
				t.Fatalf("期望命中 %s，实际 %+v", c.code, g.Findings)
			}
			if len(g.SafeEntries) != 1 || g.Rejected != 1 {
				t.Fatalf("应仅保留 1 条安全条目并拒绝 1 条，safe=%d rejected=%d",
					len(g.SafeEntries), g.Rejected)
			}
		})
	}
}

func TestAuditGameClasspathTooMany(t *testing.T) {
	root, libs, _ := gameRoots(t)
	var entries []string
	for i := 0; i < maxGameClasspathEntries+1; i++ {
		entries = append(entries, filepath.Join(libs, "j", itoaForTest(i)+".jar"))
	}
	g := AuditGameClasspath(entries, []string{root})
	if !gameFindingsHasCode(g.Findings, "gcp-too-many") {
		t.Fatal("条目数超限应命中 gcp-too-many")
	}
}

func TestAuditGameClasspathAllRejected(t *testing.T) {
	root, _, _ := gameRoots(t)
	g := AuditGameClasspath([]string{filepath.Join(t.TempDir(), "a.jar")}, []string{root})
	if !gameFindingsHasCode(g.Findings, "gcp-all-rejected") {
		t.Fatal("全部不安全时应命中 gcp-all-rejected")
	}
	if !g.HasCritical() {
		t.Fatal("应判 critical")
	}
}

func TestAuditGameLocalPaths(t *testing.T) {
	root, libs, versions := gameRoots(t)
	natives := filepath.Join(versions, "1.20-natives")
	assets := filepath.Join(root, "assets")
	if a := AuditGameLocalPaths(natives, libs, assets, []string{root}); a.HasCritical() {
		t.Fatalf("正常本地路径应放行，首个 code=%s", a.FirstCriticalCode())
	}
	bad := AuditGameLocalPaths(`\\host\share\nat`, libs, assets, []string{root})
	if !gameFindingsHasCode(bad.Findings, "localpath-unc") {
		t.Fatal("UNC natives 应命中 localpath-unc")
	}
	outside := AuditGameLocalPaths(filepath.Join(t.TempDir(), "n"), libs, "", []string{root})
	if !gameFindingsHasCode(outside.Findings, "localpath-outside") {
		t.Fatal("越界 natives 应命中 localpath-outside")
	}
	empty := AuditGameLocalPaths("", libs, "", []string{root})
	if !gameFindingsHasCode(empty.Findings, "localpath-empty") {
		t.Fatal("空 natives 应命中 localpath-empty")
	}
}

func gameFindingsHasCode(fs []LaunchFinding, code string) bool {
	for _, f := range fs {
		if f.Code == code {
			return true
		}
	}
	return false
}

func gameAuditHasWarn(g *GameClasspathAudit, code string) bool {
	for _, f := range g.Findings {
		if f.Code == code && f.Severity == launchSeverityWarn {
			return true
		}
	}
	return false
}
