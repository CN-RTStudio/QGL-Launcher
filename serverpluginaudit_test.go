package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func writePluginJar(t *testing.T, dir, name string, entries map[string]string) {
	t.Helper()
	path := filepath.Join(dir, name)
	handle, err := os.Create(path)
	if err != nil {
		t.Fatalf("create jar: %v", err)
	}
	writer := zip.NewWriter(handle)
	for entryName, content := range entries {
		entry, err := writer.Create(entryName)
		if err != nil {
			t.Fatalf("create entry %s: %v", entryName, err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatalf("write entry %s: %v", entryName, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("close jar: %v", err)
	}
}

func pluginServerDir(t *testing.T, present bool) string {
	t.Helper()
	root := t.TempDir()
	if !present {
		return root
	}
	if err := os.MkdirAll(filepath.Join(root, "plugins"), 0o700); err != nil {
		t.Fatalf("mkdir plugins: %v", err)
	}
	return root
}

func TestAuditServerPluginsAbsent(t *testing.T) {
	root := pluginServerDir(t, false)
	audit, err := AuditServerPlugins(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Present || audit.Blocking() || len(audit.Findings) != 0 {
		t.Fatalf("absent plugins dir must be silent: %s", audit.Describe())
	}
}

func TestAuditServerPluginsCleanJar(t *testing.T) {
	root := pluginServerDir(t, true)
	plugins := filepath.Join(root, "plugins")
	writePluginJar(t, plugins, "shop.jar", map[string]string{
		"plugin.yml":           "name: Shop\nmain: com.example.shop.ShopPlugin\nversion: 1.0\n",
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
	})
	audit, err := AuditServerPlugins(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Jars != 1 {
		t.Fatalf("expected one jar, got %d", audit.Jars)
	}
	if audit.Blocking() || len(audit.Findings) != 0 {
		t.Fatalf("clean jar must pass: %s", audit.Describe())
	}
}

func TestAuditServerPluginsTraversalEntryBlocks(t *testing.T) {
	root := pluginServerDir(t, true)
	plugins := filepath.Join(root, "plugins")
	writePluginJar(t, plugins, "evil.jar", map[string]string{
		"plugin.yml":      "name: Evil\nmain: com.example.evil.Main\n",
		"../escape.class": "x",
	})
	audit, err := AuditServerPlugins(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("traversal entry must block: %s", audit.Describe())
	}
}

func TestAuditServerPluginsBadMainBlocks(t *testing.T) {
	root := pluginServerDir(t, true)
	plugins := filepath.Join(root, "plugins")
	writePluginJar(t, plugins, "broken.jar", map[string]string{
		"plugin.yml": "name: Broken\nmain: ../../evil.Main\n",
	})
	audit, err := AuditServerPlugins(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("illegal main class must block: %s", audit.Describe())
	}
}

func TestAuditServerPluginsMissingManifestWarns(t *testing.T) {
	root := pluginServerDir(t, true)
	plugins := filepath.Join(root, "plugins")
	writePluginJar(t, plugins, "bare.jar", map[string]string{
		"com/example/Main.class": "x",
	})
	audit, err := AuditServerPlugins(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("missing plugin.yml must warn only: %s", audit.Describe())
	}
}

func TestAuditServerPluginsDuplicateNameBlocks(t *testing.T) {
	root := pluginServerDir(t, true)
	plugins := filepath.Join(root, "plugins")
	manifest := "name: Shared\nmain: com.example.shared.Main\n"
	writePluginJar(t, plugins, "first.jar", map[string]string{"plugin.yml": manifest})
	writePluginJar(t, plugins, "second.jar", map[string]string{"plugin.yml": manifest})
	audit, err := AuditServerPlugins(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("duplicate plugin name must block: %s", audit.Describe())
	}
}

func TestAuditServerPluginsExecutableBlocks(t *testing.T) {
	root := pluginServerDir(t, true)
	plugins := filepath.Join(root, "plugins")
	if err := os.WriteFile(filepath.Join(plugins, "update.exe"), []byte("MZ"), 0o600); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	audit, err := AuditServerPlugins(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("executable in plugins must block: %s", audit.Describe())
	}
}

func TestAuditServerPluginsSymlinkBlocks(t *testing.T) {
	root := pluginServerDir(t, true)
	plugins := filepath.Join(root, "plugins")
	outside := filepath.Join(root, "outside.jar")
	writePluginJar(t, root, "outside.jar", map[string]string{"plugin.yml": "name: Out\nmain: a.B\n"})
	link := filepath.Join(plugins, "linked.jar")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	audit, err := AuditServerPlugins(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("symlinked jar must block: %s", audit.Describe())
	}
}
