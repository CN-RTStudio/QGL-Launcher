package main

// zipextract_test.go 覆盖统一安全解压内核：路径判定、预检、原子落盘、
// 符号链接 / Zip Slip / 解压炸弹 / 重复条目全部要在测试里被真实拦下。
// 测试在磁盘上造真实 zip（而不是只调纯函数），确保与生产链路一致。

import (
	"archive/zip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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

func TestPlanEntryAndTotalCaps(t *testing.T) {
	dir := t.TempDir()

	// 条目数上限。
	z1 := filepath.Join(dir, "many.zip")
	many := make([]struct {
		name string
		data []byte
		mode os.FileMode
	}, 0, 5)
	for i := 0; i < 5; i++ {
		many = append(many, struct {
			name string
			data []byte
			mode os.FileMode
		}{"maven/f" + string(rune('0'+i)) + ".jar", []byte("a"), 0644})
	}
	buildTestZip(t, z1, many)
	limCount := zipExtractLimits{EntryMax: 1 << 20, TotalMax: 1 << 20, MaxEntries: 3}
	if _, _, err := planZipEntries(openZipFiles(t, z1), []string{"maven/"}, limCount); err == nil {
		t.Fatalf("超过条目数上限必须被拒绝")
	}

	// 声明总量上限。
	z2 := filepath.Join(dir, "big.zip")
	buildTestZip(t, z2, []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"maven/big.jar", []byte("0123456789"), 0644},
	})
	limTotal := zipExtractLimits{EntryMax: 1 << 20, TotalMax: 5, MaxEntries: 100}
	if _, _, err := planZipEntries(openZipFiles(t, z2), []string{"maven/"}, limTotal); err == nil {
		t.Fatalf("声明总量超限必须在预检阶段被拒绝")
	}
}

func TestWriteZipEntrySecureEnforcesStreamLimit(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "stream.zip")
	buildTestZip(t, zipPath, []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"x.jar", []byte("0123456789"), 0644},
	})
	files := openZipFiles(t, zipPath)

	// 元数据预检放行，但落盘上限只给 3 字节：必须靠真实流式复制拦下，
	// 且临时文件被清掉。
	dest := filepath.Join(dir, "out", "x.jar")
	if _, err := writeZipEntrySecure(files[0], dest, 3); err == nil {
		t.Fatalf("实际流超过单文件上限时必须报错")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("超限时不应留下半成品目标文件")
	}
	leftovers, _ := os.ReadDir(filepath.Join(dir, "out"))
	for _, l := range leftovers {
		if strings.HasPrefix(l.Name(), ".zipextract-") {
			t.Fatalf("超限时不应留下临时文件: %s", l.Name())
		}
	}

	// 正常上限下应成功并原子就位。
	if _, err := writeZipEntrySecure(files[0], dest, 100); err != nil {
		t.Fatalf("正常解压失败: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("目标文件不存在: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("解压文件权限 = %o，期望 0600", info.Mode().Perm())
	}
}

func TestWriteZipEntryRejectsPreExistingSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside.txt")
	if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
		t.Fatalf("准备目标文件失败: %v", err)
	}
	link := filepath.Join(dir, "in.jar")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("当前环境无权创建符号链接，跳过该用例")
	}

	zipPath := filepath.Join(dir, "z.zip")
	buildTestZip(t, zipPath, []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"in.jar", []byte("pwn"), 0644},
	})
	if _, err := writeZipEntrySecure(openZipFiles(t, zipPath)[0], link, 100); err == nil {
		t.Fatalf("覆盖预置符号链接必须被拒绝")
	}
	if data, _ := os.ReadFile(target); string(data) != "secret" {
		t.Fatalf("符号链接目标被写穿，内容变成: %q", data)
	}
}

func TestSecureZipRelPathRejectsWindowsSpecialSegments(t *testing.T) {
	cases := []struct{ in, why string }{
		{"a.jar:payload", "alternate data stream"},
		{"dir/a.jar:payload.jar", "alternate data stream in sub dir"},
		{"dir/a:1.jar", "short ADS form"},
		{"a<b>.jar", "illegal angle brackets"},
		{"a|b.jar", "illegal pipe"},
		{"a?b.jar", "illegal question mark"},
		{"a*b.jar", "illegal star"},
		{"CON", "reserved device name"},
		{"dir/nul.jar", "reserved device name with extension"},
		{"dir/COM7.txt", "reserved serial device"},
		{"a.", "trailing dot"},
		{"dir/a.txt ", "trailing space"},
		{"dir/\u202eevil.jar", "bidi override"},
		{"dir/ev\u200bile.jar", "zero width space"},
		{"dir/a\tb.jar", "tab in name"},
	}
	for _, c := range cases {
		if got, ok := secureZipRelPath(c.in); ok {
			t.Errorf("secureZipRelPath(%q) 应拒绝（%s），却返回 %q", c.in, c.why, got)
		}
	}
}

func TestPlanRejectsCaseFoldedDuplicateDest(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("大小写折叠冲突只在大小写不敏感文件系统上成立")
	}
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "case.zip")
	buildTestZip(t, zipPath, []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"maven/Foo.jar", []byte("1"), 0644},
		{"maven/foo.jar", []byte("2"), 0644},
	})
	lim := zipExtractLimits{EntryMax: 1 << 20, TotalMax: 1 << 20, MaxEntries: 100}
	if _, _, err := planZipEntries(openZipFiles(t, zipPath), []string{"maven/"}, lim); err == nil {
		t.Fatalf("仅大小写不同的同路径条目必须被拒绝")
	}
}

// TestExtractRejectsSymlinkedParentDir 复现"预置目录链接"逃逸：解压目标里
// 已存在一个指向盘外的目录链接，字面路径仍在根内，真实父目录却在根外。
func TestExtractRejectsSymlinkedParentDir(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0700); err != nil {
		t.Fatalf("准备盘外目录失败: %v", err)
	}
	dest := filepath.Join(base, "dest")
	if err := os.MkdirAll(dest, 0700); err != nil {
		t.Fatalf("准备解压目录失败: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dest, "sub")); err != nil {
		t.Skip("当前环境无权创建目录符号链接，跳过该用例")
	}

	zipPath := filepath.Join(base, "linkdir.zip")
	buildTestZip(t, zipPath, []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"sub/pwn.jar", []byte("pwn"), 0644},
	})
	lim := zipExtractLimits{EntryMax: 1 << 20, TotalMax: 1 << 20, MaxEntries: 100}
	if _, _, err := extractZipPrefixes(openZipFiles(t, zipPath), dest, []string{""}, lim, nil); err == nil {
		t.Fatalf("父目录为符号链接指向盘外时必须拒绝解压")
	}
	if _, err := os.Stat(filepath.Join(outside, "pwn.jar")); !os.IsNotExist(err) {
		t.Fatalf("链接目标目录被写穿: %v", err)
	}
}

func TestSecureDestUnder(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	good := []string{
		filepath.Join(root, "a.jar"),
		filepath.Join(root, "com", "acme", "b.jar"),
		root,
	}
	for _, p := range good {
		if !secureDestUnder(root, p) {
			t.Errorf("路径应在根目录内却被拒: %s", p)
		}
	}
	sibling := filepath.Join(filepath.Dir(root), "sibling", "x.jar")
	if secureDestUnder(root, sibling) {
		t.Errorf("兄弟目录路径必须被判定越界: %s", sibling)
	}
}
