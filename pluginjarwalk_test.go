package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

var walkTestReasons = pluginJarWalkReasons{
	Missing: "plugin-dir-missing",
	Read:    "plugin-dir-unreadable",
	DirLink: "plugin-dir-symlink",
	JarLink: "plugin-jar-symlink",
	JarOpen: "plugin-jar-unreadable",
	JarSize: "plugin-jar-oversized",
}

func writeTestJar(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create jar: %v", err)
	}
	defer f.Close()
	w := zip.NewWriter(f)
	for name, body := range entries {
		e, err := w.Create(name)
		if err != nil {
			t.Fatalf("create entry: %v", err)
		}
		if _, err := e.Write([]byte(body)); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
}

func TestWalkPluginJarsEmptyServerDir(t *testing.T) {
	walk := walkPluginJars("", 1<<20, walkTestReasons, nil)
	if walk.Jars != 0 {
		t.Fatalf("expected no jars, got %d", walk.Jars)
	}
	if len(walk.Issues) != 1 || walk.Issues[0].Blocking {
		t.Fatalf("expected one advisory issue, got %#v", walk.Issues)
	}
}

func TestWalkPluginJarsMissingDir(t *testing.T) {
	dir := t.TempDir()
	walk := walkPluginJars(dir, 1<<20, walkTestReasons, nil)
	if len(walk.Issues) != 1 || walk.Issues[0].Reason != walkTestReasons.Missing {
		t.Fatalf("expected missing reason, got %#v", walk.Issues)
	}
}

func TestWalkPluginJarsRejectsOversizedJar(t *testing.T) {
	dir := t.TempDir()
	plugins := filepath.Join(dir, "plugins")
	if err := os.MkdirAll(plugins, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTestJar(t, filepath.Join(plugins, "big.jar"), map[string]string{"a.txt": "hello"})
	walk := walkPluginJars(dir, 4, walkTestReasons, nil)
	if walk.Jars != 1 {
		t.Fatalf("expected one jar counted, got %d", walk.Jars)
	}
	if len(walk.Issues) != 1 || walk.Issues[0].Reason != walkTestReasons.JarSize || walk.Issues[0].Blocking {
		t.Fatalf("expected advisory size issue, got %#v", walk.Issues)
	}
}

func TestWalkPluginJarsRejectsBrokenZip(t *testing.T) {
	dir := t.TempDir()
	plugins := filepath.Join(dir, "plugins")
	if err := os.MkdirAll(plugins, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(plugins, "broken.jar"), []byte("not a zip"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	walk := walkPluginJars(dir, 1<<20, walkTestReasons, nil)
	if len(walk.Issues) != 1 || walk.Issues[0].Reason != walkTestReasons.JarOpen || !walk.Issues[0].Blocking {
		t.Fatalf("expected blocking open issue, got %#v", walk.Issues)
	}
}

func TestWalkPluginJarsVisitsValidJar(t *testing.T) {
	dir := t.TempDir()
	plugins := filepath.Join(dir, "plugins")
	if err := os.MkdirAll(plugins, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTestJar(t, filepath.Join(plugins, "good.JAR"), map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"})
	seen := 0
	walk := walkPluginJars(dir, 1<<20, walkTestReasons, func(name string, archive *zip.ReadCloser) {
		seen++
		if name != "good.JAR" {
			t.Errorf("unexpected jar name %q", name)
		}
		if len(archive.File) != 1 {
			t.Errorf("expected one entry, got %d", len(archive.File))
		}
	})
	if seen != 1 || walk.Jars != 1 || len(walk.Issues) != 0 {
		t.Fatalf("expected clean visit, got seen=%d walk=%#v", seen, walk)
	}
}

func TestWalkPluginJarsCountsNonJarEntries(t *testing.T) {
	dir := t.TempDir()
	plugins := filepath.Join(dir, "plugins")
	if err := os.MkdirAll(filepath.Join(plugins, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(plugins, "readme.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	walk := walkPluginJars(dir, 1<<20, walkTestReasons, nil)
	if walk.Jars != 0 || len(walk.Issues) != 0 {
		t.Fatalf("expected empty walk, got %#v", walk)
	}
}
