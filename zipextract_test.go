package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// zipextract_test.go 覆盖统一安全解压内核：路径判定、预检、原子落盘、
// 符号链接 / Zip Slip / 解压炸弹 / 重复条目全部要在测试里被真实拦下。
// 测试在磁盘上造真实 zip（而不是只调纯函数），确保与生产链路一致。

func TestSecureZipRelPath(t *testing.T) {
	okCases := map[string]string{
		"a.txt":          "a.txt",
		"dir/a.txt":      "dir/a.txt",
		"dir/./a.txt":    "dir/a.txt",
		"dir//a.txt":     "dir/a.txt",
		"./a.txt":        "a.txt",
		"x/y/z/":         "x/y/z",
		"深目录/文件-名_1.dll": "深目录/文件-名_1.dll",
	}
	for in, want := range okCases {
		got, ok := secureZipRelPath(in)
		if !ok || got != want {
			t.Errorf("secureZipRelPath(%q) = %q,%v，期望 %q,true", in, got, ok, want)
		}
	}

	bad := []string{
		"", ".", "..", "../a", "a/../../b", "a/../..",
		"/etc/passwd", "/a.txt",
		`..\windows`, `a\b.txt`,
		"C:/Windows/x", "c:x",
		"a\x00b", "a/../",
		"dir/sub/../a.txt",
	}
	for _, in := range bad {
		if got, ok := secureZipRelPath(in); ok {
			t.Errorf("secureZipRelPath(%q) 应当被拒绝，却返回 %q", in, got)
		}
	}
}

// buildTestZip 在 w 里写入一组 (name, content, mode) 条目。
func buildTestZip(t *testing.T, path string, entries []struct {
	name string
	data []byte
	mode os.FileMode
}) {
	t.Helper()
	zf, err := os.Create(path)
	if err != nil {
		t.Fatalf("创建测试 zip 失败: %v", err)
	}
	defer zf.Close()

	zw := zip.NewWriter(zf)
	for _, e := range entries {
		fh := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		fh.SetMode(e.mode)
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatalf("创建 zip 条目头失败 %s: %v", e.name, err)
		}
		if len(e.data) > 0 {
			if _, err := w.Write(e.data); err != nil {
				t.Fatalf("写入 zip 条目失败 %s: %v", e.name, err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("关闭 zip writer 失败: %v", err)
	}
}

func openZipFiles(t *testing.T, path string) []*zip.File {
	t.Helper()
	r, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("打开测试 zip 失败: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return r.File
}

func TestExtractZipPrefixesHappyPath(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "good.zip")
	buildTestZip(t, zipPath, []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"maven/com/acme/a.jar", []byte("AAA"), 0644},
		{"maven/com/acme/nested/b.jar", []byte("BBBB"), 0644},
		{"maven/com/acme/skip.txt", []byte("XX"), 0644},
		{"ignored/readme.txt", []byte("NO"), 0644},
	})

	dest := filepath.Join(dir, "libs")
	lim := zipExtractLimits{EntryMax: 1 << 20, TotalMax: 1 << 20, MaxEntries: 100}
	plan, declared, err := planZipEntries(openZipFiles(t, zipPath), []string{"maven/"}, lim)
	if err != nil {
		t.Fatalf("预检失败: %v", err)
	}
	if len(plan) != 3 {
		t.Fatalf("计划条目数 = %d，期望 3", len(plan))
	}
	if declared != 9 {
		t.Fatalf("声明总量 = %d，期望 9", declared)
	}

	n, count, err := extractZipPrefixes(openZipFiles(t, zipPath), dest, []string{"maven/"}, lim, nil)
	if err != nil {
		t.Fatalf("解压失败: %v", err)
	}
	if count != 3 || n != 9 {
		t.Fatalf("解压 count=%d bytes=%d，期望 3/9", count, n)
	}
	if data, err := os.ReadFile(filepath.Join(dest, "com", "acme", "a.jar")); err != nil || string(data) != "AAA" {
		t.Fatalf("a.jar 内容不符: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "readme.txt")); !os.IsNotExist(err) {
		t.Fatalf("非前缀条目不应被解压")
	}
}

func TestPlanRejectsZipSlip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "evil.zip")
	evilNames := []string{
		"maven/../../../tmp/pwn.jar",
		"maven/../escape.jar",
		"maven/./../../x",
		"maven//../../y",
	}
	entries := make([]struct {
		name string
		data []byte
		mode os.FileMode
	}, 0, len(evilNames))
	for _, n := range evilNames {
		entries = append(entries, struct {
			name string
			data []byte
			mode os.FileMode
		}{n, []byte("x"), 0644})
	}
	buildTestZip(t, zipPath, entries)

	lim := zipExtractLimits{EntryMax: 1 << 20, TotalMax: 1 << 20, MaxEntries: 100}
	if _, _, err := planZipEntries(openZipFiles(t, zipPath), []string{"maven/"}, lim); err == nil {
		t.Fatalf("含 Zip Slip 路径的 zip 必须被拒绝")
	}
}

func TestPlanRejectsSymlinkAndSpecialEntries(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "link.zip")
	buildTestZip(t, zipPath, []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"maven/ok.jar", []byte("ok"), 0644},
		{"maven/link", []byte("../../../outside"), os.ModeSymlink | 0644},
	})
	lim := zipExtractLimits{EntryMax: 1 << 20, TotalMax: 1 << 20, MaxEntries: 100}
	_, _, err := planZipEntries(openZipFiles(t, zipPath), []string{"maven/"}, lim)
	if err == nil {
		t.Fatalf("含符号链接条目的 zip 必须被拒绝")
	}
	if !strings.Contains(err.Error(), "特殊类型") {
		t.Fatalf("错误信息应说明是特殊类型，实际: %v", err)
	}
}

func TestPlanRejectsDuplicateDest(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "dup.zip")
	buildTestZip(t, zipPath, []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"maven/a.jar", []byte("1"), 0644},
		{"maven/./a.jar", []byte("2"), 0644},
	})
	lim := zipExtractLimits{EntryMax: 1 << 20, TotalMax: 1 << 20, MaxEntries: 100}
	if _, _, err := planZipEntries(openZipFiles(t, zipPath), []string{"maven/"}, lim); err == nil {
		t.Fatalf("折叠后落向同一路径的重复条目必须被拒绝")
	}
}

// TestExtractRejectsSymlinkedParentDir 复现"预置目录链接"逃逸：解压目标里
// 已存在一个指向盘外的目录链接，字面路径仍在根内，真实父目录却在根外。
