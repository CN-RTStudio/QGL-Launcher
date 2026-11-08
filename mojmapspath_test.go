package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeMojmapsMappingsPathValid(t *testing.T) {
	mcDir := filepath.Clean(t.TempDir())
	got, ok := SafeMojmapsMappingsPath(mcDir, "com.mojang:client:1.21", "txt")
	if !ok {
		t.Fatal("合法官方坐标应当通过")
	}
	rel, err := filepath.Rel(filepath.Join(mcDir, "libraries"), got)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		t.Fatalf("结果必须落在 libraries 内, got=%v rel=%v", got, rel)
	}
	if filepath.Base(got) != "client-1.21-mappings.txt" {
		t.Fatalf("文件名异常: %s", filepath.Base(got))
	}
}

func TestSafeMojmapsMappingsPathTraversal(t *testing.T) {
	mcDir := filepath.Clean(t.TempDir())
	bad := []struct {
		coord string
		ext   string
	}{
		{"com.mojang:client:../../../../../../Windows/Temp/x", "txt"},
		{"com.mojang:../evil:1.0", "txt"},
		{"g:a:v", "../../x"},
		{"g:a:v", `txt\x`},
		{"g:a:v", "txt/../a"},
		{"g:a", "txt"},
		{"g:a:v:extra", "txt"},
		{"g:a:v", "EXE"},
		{"g:a:v", ""},
		{"g::v", "txt"},
	}
	for _, c := range bad {
		if p, ok := SafeMojmapsMappingsPath(mcDir, c.coord, c.ext); ok {
			t.Errorf("恶意坐标必须被拒绝 coord=%q ext=%q got=%v", c.coord, c.ext, p)
		}
	}
}
