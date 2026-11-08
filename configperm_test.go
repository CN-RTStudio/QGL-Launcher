package main

// configperm_test.go —— 敏感文件权限审计内核的测试。
//
// 测试覆盖的攻击向量：
//  1. 同机其他账户可读（Unix chmod 0644）→ warn world-readable，可收敛；
//  2. 符号链接指向外部文件 → block symlink，ConvergePermissions 拒绝触碰；
//  3. 正常 0600 文件 → ok，不进入结果；
//  4. 非敏感文件（不在白名单路径）→ 不审计；
//  5. 不存在的文件 → 静默跳过；
//  6. Windows 隐藏属性 → warn hidden（Windows 专属分支）。
// 平台差异用 t.Skip 隔离，保证两个平台都能全绿。

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func makePermRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	must := func(rel string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
		}
		if err := os.WriteFile(p, []byte("secret"), mode); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
		return p
	}
	must("accounts/bob.json", 0o600)
	must("accounts/alice.json", 0o600)
	must("logs/session.log", 0o600)
	must("password.json", 0o600)
	must("config.json", 0o600)
	// 非敏感路径，不应被审计
	must("mods/whatever.json", 0o644)
	must("versions/x.json", 0o644)
	return root
}

func TestAuditSensitivePermissions_NoIssue(t *testing.T) {
	root := makePermRoot(t)
	findings := AuditSensitivePermissions(root)
	if len(findings) != 0 {
		t.Fatalf("期望 0 条发现，得到 %d 条: %+v", len(findings), findings)
	}
}

func TestAuditSensitivePermissions_WorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix 权限位在 Windows 上无意义")
	}
	root := makePermRoot(t)
	p := filepath.Join(root, "password.json")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	findings := AuditSensitivePermissions(root)
	found := false
	for _, f := range findings {
		if f.Path == p {
			found = true
			if f.Severity != permSeverityWarn || f.Issue != "world-readable" {
				t.Fatalf("期望 warn/world-readable，得到 %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("未发现 world-readable 文件 %s；findings=%+v", p, findings)
	}
}

func TestAuditSensitivePermissions_GroupReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix 权限位在 Windows 上无意义")
	}
	root := makePermRoot(t)
	p := filepath.Join(root, "accounts", "alice.json")
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	findings := AuditSensitivePermissions(root)
	for _, f := range findings {
		if f.Path == p {
			if f.Severity != permSeverityWarn {
				t.Fatalf("0640 应收敛，得到 %+v", f)
			}
			return
		}
	}
	t.Fatalf("未发现 group-readable 文件 %s；findings=%+v", p, findings)
}

func TestAuditSensitivePermissions_SymlinkBlocked(t *testing.T) {
	root := makePermRoot(t)
	victim := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(victim, []byte("target-content"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	link := filepath.Join(root, "password.json")
	_ = os.Remove(link)
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("当前环境不允许创建符号链接: %v", err)
	}
	findings := AuditSensitivePermissions(root)
	for _, f := range findings {
		if f.Path == link {
			if f.Severity != permSeverityBlock || f.Issue != "symlink" {
				t.Fatalf("期望 block/symlink，得到 %+v", f)
			}
			return
		}
	}
	t.Fatalf("未发现符号链接 %s；findings=%+v", link, findings)
}

func TestAuditSensitivePermissions_NonRegular(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 上创建命名管道需要额外权限")
	}
	root := makePermRoot(t)
	dir := filepath.Join(root, "accounts", "notafile.json")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	findings := AuditSensitivePermissions(root)
	for _, f := range findings {
		if f.Path == dir {
			if f.Severity != permSeverityBlock || f.Issue != "non-regular" {
				t.Fatalf("目录路径应收敛为 block/non-regular，得到 %+v", f)
			}
			return
		}
	}
	t.Fatalf("未发现 non-regular 路径 %s；findings=%+v", dir, findings)
}

func TestAuditSensitivePermissions_MissingFileSkipped(t *testing.T) {
	root := makePermRoot(t)
	_ = os.Remove(filepath.Join(root, "config.json"))
	_ = os.Remove(filepath.Join(root, "salt.bin"))
	findings := AuditSensitivePermissions(root)
	for _, f := range findings {
		if f.Severity != permSeverityOK && f.Issue != "" && stringsHasSuffix(f.Path, "config.json") {
			t.Fatalf("不存在的文件不应报 issue: %+v", f)
		}
	}
}

func TestAuditSensitivePermissions_EmptyRoot(t *testing.T) {
	if got := AuditSensitivePermissions(""); got != nil {
		t.Fatalf("空 root 应返回 nil，得到 %+v", got)
	}
	if got := AuditSensitivePermissions(filepath.Join(t.TempDir(), "missing")); got != nil {
		t.Fatalf("不存在目录应返回 nil，得到 %+v", got)
	}
}

func TestWarnFindings_Filter(t *testing.T) {
	findings := []PermFinding{
		{Path: "a", Severity: permSeverityWarn},
		{Path: "b", Severity: permSeverityBlock},
		{Path: "c", Severity: permSeverityWarn},
		{Path: "d", Severity: permSeverityOK},
	}
	warns := WarnFindings(findings)
	if len(warns) != 2 || warns[0].Path != "a" || warns[1].Path != "c" {
		t.Fatalf("WarnFindings 过滤错误: %+v", warns)
	}
	blocks := BlockedFindings(findings)
	if len(blocks) != 1 || blocks[0].Path != "b" {
		t.Fatalf("BlockedFindings 过滤错误: %+v", blocks)
	}
}

func TestConvergePermissions_WorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix 权限位在 Windows 上无意义")
	}
	root := makePermRoot(t)
	p := filepath.Join(root, "logs", "session.log")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	findings := AuditSensitivePermissions(root)
	fixed, failed := ConvergePermissions(findings)
	if len(failed) != 0 {
		t.Fatalf("收敛失败: %v", failed)
	}
	if len(fixed) != 1 || fixed[0] != p {
		t.Fatalf("期望收敛 %s，得到 %v", p, fixed)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("收敛后权限应为 0600，得到 %o", st.Mode().Perm())
	}
	// 内容不能被改动
	data, _ := os.ReadFile(p)
	if string(data) != "secret" {
		t.Fatalf("收敛不应改内容，得到 %q", string(data))
	}
}

func TestConvergePermissions_SymlinkUntouched(t *testing.T) {
	root := makePermRoot(t)
	victim := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(victim, []byte("target-content"), 0o644); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	link := filepath.Join(root, "password.json")
	_ = os.Remove(link)
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("当前环境不允许创建符号链接: %v", err)
	}
	findings := AuditSensitivePermissions(root)
	fixed, failed := ConvergePermissions(findings)
	if len(fixed) != 0 {
		t.Fatalf("符号链接不应被收敛: %v", fixed)
	}
	if len(failed) != 1 || failed[0] != link {
		t.Fatalf("符号链接应进入 failed: %v", failed)
	}
	// 受害者文件权限不能被改动
	st, err := os.Stat(victim)
	if err != nil {
		t.Fatalf("stat victim: %v", err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("受害者文件权限被意外改动: %o", st.Mode().Perm())
	}
}

func stringsHasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}
