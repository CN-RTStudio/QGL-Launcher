package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainsControlChar(t *testing.T) {
	bad := []string{"a\x00b", "x\ny", "\t", "del\x7f"}
	for _, s := range bad {
		if !containsControlChar(s) {
			t.Errorf("%q 含控制字符，应判定为 true", s)
		}
	}
	good := []string{"C:\\Temp\\jdk.exe", `\\server\share\jre.msi`, "normal path"}
	for _, s := range good {
		if containsControlChar(s) {
			t.Errorf("%q 不含控制字符，误判", s)
		}
	}
}

func TestHasAlternateDataStream(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{`C:\Temp\jdk.exe`, false},        // 卷标冒号合法
		{`C:\Temp\jdk.exe:evil`, true},   // NTFS ADS
		{`C:\Temp\folder:stream\x`, true},
		{`C:jdk.msi`, false},              // 卷相对路径，第二个字符后无冒号
		{`\\server\share\jre.exe`, false}, // UNC 正常路径
		{`\\server\share\jre.exe:ads`, true},
	}
	for _, c := range cases {
		if got := hasAlternateDataStream(c.path); got != c.want {
			t.Errorf("hasAlternateDataStream(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func writeDummyInstaller(t *testing.T, dir, name string, size int64) string {
	t.Helper()
	p := filepath.Join(dir, name)
	data := make([]byte, int(size))
	for i := range data {
		data[i] = byte('A' + (i % 26))
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("写测试安装包失败: %v", err)
	}
	return p
}

func TestValidateInstallerPackageHappy(t *testing.T) {
	dir := t.TempDir()
	exe := writeDummyInstaller(t, dir, "jdk-setup.exe", minJavaInstallerBytes+100)
	if err := validateInstallerPackage(exe, false); err != nil {
		t.Fatalf("正常 exe 应通过校验: %v", err)
	}
	msi := writeDummyInstaller(t, dir, "java.msi", minJavaInstallerBytes+100)
	if err := validateInstallerPackage(msi, true); err != nil {
		t.Fatalf("正常 msi 应通过校验: %v", err)
	}
}

func TestValidateInstallerPackageRejects(t *testing.T) {
	dir := t.TempDir()
	good := writeDummyInstaller(t, dir, "jdk.exe", minJavaInstallerBytes+10)

	// 类型声明与扩展名不符。
	if err := validateInstallerPackage(good, true); err == nil {
		t.Fatal("exe 文件按 msi 校验应被拒绝")
	}

	// 错误扩展名。
	wrong := writeDummyInstaller(t, dir, "jdk.bin", minJavaInstallerBytes+10)
	if err := validateInstallerPackage(wrong, false); err == nil {
		t.Fatal(".bin 扩展名应被拒绝")
	}

	// 空 / 过小文件。
	small := writeDummyInstaller(t, dir, "tiny.exe", 2)
	if err := validateInstallerPackage(small, false); err == nil {
		t.Fatal("体积异常偏小的安装包应被拒绝")
	}

	// 不存在。
	if err := validateInstallerPackage(filepath.Join(dir, "missing.exe"), false); err == nil {
		t.Fatal("不存在的安装包应报错")
	}

	// 目录而不是文件。
	if err := validateInstallerPackage(dir, false); err == nil {
		t.Fatal("目录路径应被拒绝")
	}

	// ADS 路径。
	if err := validateInstallerPackage(good+":secret", false); err == nil {
		t.Fatal("NTFS 备用数据流路径应被拒绝")
	}

	// 控制字符 / 引号。
	if err := validateInstallerPackage(good+"\x00", false); err == nil {
		t.Fatal("含 NUL 的路径应被拒绝")
	}
	if err := validateInstallerPackage(`C:\Temp\a"b.exe`, false); err == nil {
		t.Fatal("含引号的路径应被拒绝")
	}
}

func TestRemoveStaleInstaller(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "stale.msi")
	// 不存在：无错误。
	if err := removeStaleInstaller(p); err != nil {
		t.Fatalf("删除不存在的文件不应报错: %v", err)
	}
	// 存在：删掉。
	writeDummyInstaller(t, dir, "stale.msi", 100)
	if err := removeStaleInstaller(p); err != nil {
		t.Fatalf("删除残留安装包失败: %v", err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatal("残留安装包应已不存在")
	}
}

// 符号链接场景：Windows 上普通用户可能无权创建符号链接，无权时跳过；
// 有权限时必须确认链接被拒绝且清理不跟随链接。
func TestValidateInstallerPackageSymlink(t *testing.T) {
	dir := t.TempDir()
	target := writeDummyInstaller(t, dir, "real.exe", minJavaInstallerBytes+10)
	link := filepath.Join(dir, "link.exe")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("当前环境无创建符号链接权限，跳过")
	}
	if err := validateInstallerPackage(link, false); err == nil {
		t.Fatal("指向真实文件的符号链接也应被拒绝，防 TEMP 预置链接")
	}
	// removeStaleInstaller 只删链接、不动目标。
	if err := removeStaleInstaller(link); err != nil {
		t.Fatalf("删除符号链接失败: %v", err)
	}
	if _, err := os.Lstat(target); err != nil {
		t.Fatalf("清理链接时不应删除链接目标: %v", err)
	}
}
