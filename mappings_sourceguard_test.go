package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMappingsURLAllowed(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://piston-data.mojang.com/v1/objects/abc/client_mappings.txt", true},
		{"https://bmclapi2.bangbang93.com/v1/objects/abc/client_mappings.txt", true},
		{"http://piston-data.mojang.com/v1/objects/abc/client_mappings.txt", false},
		{"https://evil.example.com/client_mappings.txt", false},
		{"https://piston-data.mojang.com/../../etc/passwd", false},
		{"https://piston-data.mojang.com/v1/objects/abc/'; Remove-Item -Recurse C:\\", false},
		{"https://user:pass@piston-data.mojang.com/a.txt", false},
		{"https://piston-data.mojang.com", false},
		{"", false},
	}
	for _, c := range cases {
		if got := mappingsURLAllowed(c.url); got != c.want {
			t.Errorf("mappingsURLAllowed(%q)=%v want %v", c.url, got, c.want)
		}
	}
}

func TestArchiveEntryPathInside(t *testing.T) {
	base := filepath.Join(t.TempDir(), "libraries")
	inside := []string{"net/minecraft/client/1.19.2/client-1.19.2.jar", "a/b/c.txt"}
	outside := []string{"../evil.dll", "../../evil.dll", "/abs/evil.dll", `..\evil.dll`, "a/../../evil.dll", "C:/evil.dll", "a/b:c.txt", ""}
	for _, name := range inside {
		p, ok := archiveEntryPathInside(base, name)
		if !ok || !strings.HasPrefix(p, base+string(filepath.Separator)) {
			t.Errorf("inside entry %q rejected or escaped: %q", name, p)
		}
	}
	for _, name := range outside {
		if p, ok := archiveEntryPathInside(base, name); ok {
			t.Errorf("outside entry %q accepted as %q", name, p)
		}
	}
}
