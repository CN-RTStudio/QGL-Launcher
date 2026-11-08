package main

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// launchTargetRoots 构造一对（安装根, 工作目录）绝对路径，避免在测试里硬编码盘符。
func launchTargetRoots(t *testing.T) (root, workDir string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "opengl-root")
	workDir = filepath.Join(root, "servers", "s1")
	return root, workDir
}

func TestAuditJavaExe(t *testing.T) {
	cases := []struct {
		name string
		exe  string
		want string // 期望出现的 critical code，空串表示放行
	}{
		{"empty", "", "java-empty"},
		{"relative", "java", "java-not-absolute"},
		{"control", withCtrlPath(), "java-control"},
		{"unc", `\\host\share\java.exe`, "java-unc"},
		{"traversal", filepath.Join(string(filepath.Separator), "opt", "..", "etc", "java"), "java-traversal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := auditJavaExe(c.exe)
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("expected clean, got %v", got)
				}
				return
			}
			if !findingHasCode(got, c.want) {
				t.Fatalf("expected code %s, got %v", c.want, got)
			}
		})
	}
}

// withCtrlPath 拼一个含 NUL 之外控制字符（\x01）的绝对路径，验证控制字符拦截。
func withCtrlPath() string {
	return filepath.Join(string(filepath.Separator), "usr", "bin", "ja\x01va")
}

func TestAuditWorkDir(t *testing.T) {
	root, workDir := launchTargetRoots(t)
	if a := auditWorkDir(workDir, []string{root}); len(a) != 0 {
		t.Fatalf("合法工作目录应放行: %v", a)
	}
	bad := []struct {
		dir   string
		roots []string
		code  string
	}{
		{"", []string{root}, "workdir-empty"},
		{filepath.Join(root, "..", "..", "etc"), []string{root}, "workdir-traversal"},
		{filepath.Join(string(filepath.Separator), "elsewhere"), []string{root}, "workdir-outside"},
		{`\\host\share\s`, []string{root}, "workdir-unc"},
	}
	for _, c := range bad {
		if !findingHasCode(auditWorkDir(c.dir, c.roots), c.code) {
			t.Fatalf("目录 %q 应命中 %s，实际 %v", c.dir, c.code, auditWorkDir(c.dir, c.roots))
		}
	}
}

func TestAuditJarRelPath(t *testing.T) {
	root, workDir := launchTargetRoots(t)
	if got := auditJarRelPath(workDir, "1.20-server.jar", []string{root}); len(got) != 0 {
		t.Fatalf("合法 jar 应放行: %v", got)
	}
	// 子目录内的 jar 只要不逃逸也允许。
	sub := filepath.Join("lib", "s.jar")
	if got := auditJarRelPath(workDir, sub, []string{root}); len(got) != 0 {
		t.Fatalf("子目录 jar 应放行: %v", got)
	}
	bad := []struct {
		jar  string
		code string
	}{
		{"../evil.jar", "jar-traversal"},
		{"../../x-server.jar", "jar-traversal"},
		{filepath.Join(string(filepath.Separator), "abs", "x.jar"), "jar-absolute"},
		{`\\host\share\x.jar`, "jar-absolute"},
		{"note.txt", "jar-not-jar"},
		{"lib/../a.jar", "jar-traversal"},
	}
	for _, c := range bad {
		if !findingHasCode(auditJarRelPath(workDir, c.jar, []string{root}), c.code) {
			t.Fatalf("jar %q 应命中 %s，实际 %v", c.jar, c.code, auditJarRelPath(workDir, c.jar, []string{root}))
		}
	}
	// 未使用 -jar（空串）合法。
	if got := auditJarRelPath(workDir, "", []string{root}); len(got) != 0 {
		t.Fatalf("空 jar 应视为未使用 -jar: %v", got)
	}
}

func TestAuditClasspath(t *testing.T) {
	root, workDir := launchTargetRoots(t)
	good := []string{"lib/a.jar", "lib/b.jar"}
	if got := auditClasspath(workDir, good, []string{root}); len(got) != 0 {
		t.Fatalf("合法 classpath 应放行: %v", got)
	}
	if !findingHasCode(auditClasspath(workDir, []string{""}, []string{root}), "cp-empty") {
		t.Fatal("空 classpath 条目应拒绝")
	}
	if !findingHasCode(auditClasspath(workDir, []string{"../x.jar"}, []string{root}), "cp-traversal") {
		t.Fatal("穿越 classpath 条目应拒绝")
	}
	if !findingHasCode(auditClasspath(workDir, []string{filepath.Join(string(filepath.Separator), "abs.jar")}, []string{root}), "cp-absolute") {
		t.Fatal("绝对 classpath 条目应拒绝")
	}
	many := make([]string, maxClasspathEntries+1)
	for i := range many {
		many[i] = "x.jar"
	}
	if !findingHasCode(auditClasspath(workDir, many, []string{root}), "cp-too-many") {
		t.Fatal("超长 classpath 应拒绝")
	}
}

func TestAuditMainClass(t *testing.T) {
	for _, good := range []string{"", "net.minecraft.server.MinecraftServer", "a/b.C", "com.foo.Inner$Bar"} {
		if got := auditMainClass(good); len(got) != 0 {
			t.Fatalf("主类 %q 应放行，实际 %v", good, got)
		}
	}
	bad := map[string]string{
		"-version":                  "main-option-like",
		"@evil.txt":                 "main-option-like",
		"a.b..C":                    "main-empty-segment",
		"a/b/":                      "main-empty-class",
		"com.foo.Bad Class":         "main-control",
		"com.foo.Bad\x00Class":      "main-control",
		"net.minecraft.Run;calc":    "main-bad-char",
	}
	for name, code := range bad {
		if !findingHasCode(auditMainClass(name), code) {
			t.Fatalf("主类 %q 应命中 %s，实际 %v", name, code, auditMainClass(name))
		}
	}
}

func TestAuditProgramArgs(t *testing.T) {
	// 主类后的 --/- 选项是合法的，不能当 JVM 选项拦。
	good := []string{"--username", "alice", "--server", "host", "nogui", "-p", "25565"}
	if got := auditProgramArgs(good); len(got) != 0 {
		t.Fatalf("合法程序参数应放行: %v", got)
	}
	if !findingHasCode(auditProgramArgs([]string{"a\x00b"}), "arg-control") {
		t.Fatal("含控制字符的程序参数应拒绝")
	}
	if !findingHasCode(auditProgramArgs([]string{strings.Repeat("x", maxLaunchArgBytes+1)}), "arg-long") {
		t.Fatal("过长程序参数应拒绝")
	}
	many := make([]string, maxLaunchArgs+1)
	if !findingHasCode(auditProgramArgs(many), "args-too-many") {
		t.Fatal("程序参数数量过多应拒绝")
	}
}

func TestAuditMemory(t *testing.T) {
	if got := auditMemory(1024, 4096); len(got) != 0 {
		t.Fatalf("正常内存应放行: %v", got)
	}
	if !findingHasCode(auditMemory(0, 4096), "mem-min-small") {
		t.Fatal("最小内存为 0 应拒绝")
	}
	if !findingHasCode(auditMemory(8192, 4096), "mem-order") {
		t.Fatal("min>max 应拒绝")
	}
	if !findingHasCode(auditMemory(1024, maxMemoryMBUpperBound+1), "mem-max-huge") {
		t.Fatal("超大 max 应至少告警")
	}
}

func TestAuditServerLaunchVersionTraversal(t *testing.T) {
	root, workDir := launchTargetRoots(t)
	// 正常版本名拼出的 jar 位于工作目录内，放行。
	a := AuditServerLaunch(workDir, "1.20.4", 1024, 4096, []string{root})
	if a.HasCritical() {
		t.Fatalf("正常服务器启动目标应放行: %v", a.Findings)
	}
	// 版本名里塞穿越：拼出的 -jar 目标逃逸工作目录，必须阻断。
	bad := AuditServerLaunch(workDir, "../../evil", 1024, 4096, []string{root})
	if !bad.HasCritical() || !findingHasCode(bad.Findings, "jar-traversal") {
		t.Fatalf("穿越版本名拼出的 jar 必须阻断: %v", bad.Findings)
	}
	// 绝对路径样式的版本名同样必须阻断。
	absV := AuditServerLaunch(workDir, strings.TrimPrefix(filepath.Join(string(filepath.Separator), "tmp", "x"), string(filepath.Separator)), 1024, 4096, []string{root})
	if !absV.HasCritical() {
		t.Fatalf("绝对路径版本名必须阻断: %v", absV.Findings)
	}
}

func TestAuditLaunchPlanEntryRequirement(t *testing.T) {
	root, workDir := launchTargetRoots(t)
	// 既无 jar 也无主类：必须报入口缺失。
	missing := AuditLaunchPlan(LaunchPlan{
		JavaExe:     jAbs(),
		WorkDir:     workDir,
		MinMemoryMB: 1024,
		MaxMemoryMB: 4096,
		AllowedRoots: []string{root},
	})
	if !findingHasCode(missing.Findings, "entry-missing") {
		t.Fatalf("缺少启动入口应报错: %v", missing.Findings)
	}
}

func TestLaunchAuditCountsAndFirstCritical(t *testing.T) {
	a := &LaunchAudit{}
	a.add("x", launchSeverityCritical, "f", "d")
	a.add("y", launchSeverityWarn, "f", "d")
	if a.Critical != 1 || a.Warns != 1 || !a.HasCritical() {
		t.Fatalf("计数错误: %+v", a)
	}
	if a.FirstCriticalCode() != "x" {
		t.Fatalf("FirstCriticalCode 错误: %s", a.FirstCriticalCode())
	}
}

// ---- 小工具 ----

func findingHasCode(findings []LaunchFinding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func jAbs() string {
	return filepath.Join(string(filepath.Separator), "usr", "lib", "jvm", "bin", "java")
}

// javaExeForTest 返回当前平台下能通过 auditJavaExe 的绝对 java 路径形态（仅命名形态，
// 不要求文件真实存在——审计内核只判定不触碰文件系统）。
func javaExeForTest() string {
	base := jAbs()
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

func TestAuditExternalJVMAcceptsContainedAbsJar(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	work := filepath.Join(root, "bin")
	jar := filepath.Join(work, "installer.jar")
	audit := AuditExternalJVM(ExternalJVMPlan{
		JavaExe:      javaExeForTest(),
		WorkDir:      work,
		JarAbsPath:   jar,
		AllowedRoots: []string{root},
	})
	if audit.HasCritical() {
		t.Fatalf("目录内绝对 jar 应放行，得到 %s", audit.FirstCriticalCode())
	}
}

func TestAuditExternalJVMRejectsTraversalAndOutside(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	work := filepath.Join(root, "bin")
	outside := filepath.Join(t.TempDir(), "evil", "installer.jar")
	cases := []struct {
		name string
		plan ExternalJVMPlan
		want string
	}{
		{
			"jar-outside-root",
			ExternalJVMPlan{JavaExe: jAbs(), WorkDir: work, JarAbsPath: outside, AllowedRoots: []string{root}},
			"absjar-outside",
		},
		{
			"jar-unc",
			ExternalJVMPlan{JavaExe: jAbs(), WorkDir: work, JarAbsPath: `\\host\share\a.jar`, AllowedRoots: []string{root}},
			"absjar-unc",
		},
		{
			"jar-traversal",
			ExternalJVMPlan{JavaExe: jAbs(), WorkDir: work, JarAbsPath: filepath.Join(root, "..", "evil.jar"), AllowedRoots: []string{root}},
			"absjar-traversal",
		},
		{
			"jar-not-jar",
			ExternalJVMPlan{JavaExe: jAbs(), WorkDir: work, JarAbsPath: filepath.Join(work, "installer.exe"), AllowedRoots: []string{root}},
			"absjar-not-jar",
		},
		{
			"cp-outside",
			ExternalJVMPlan{
				JavaExe: jAbs(), WorkDir: work,
				Classpath:    []string{outside},
				MainClass:    "a.B",
				AllowedRoots: []string{root},
			},
			"abscp-outside",
		},
		{
			"cp-empty",
			ExternalJVMPlan{
				JavaExe: jAbs(), WorkDir: work,
				Classpath:    []string{""},
				MainClass:    "a.B",
				AllowedRoots: []string{root},
			},
			"abscp-empty",
		},
		{
			"cp-not-jar",
			ExternalJVMPlan{
				JavaExe: jAbs(), WorkDir: work,
				Classpath:    []string{filepath.Join(work, "lib.txt")},
				MainClass:    "a.B",
				AllowedRoots: []string{root},
			},
			"abscp-not-jar",
		},
		{
			"main-option-like",
			ExternalJVMPlan{JavaExe: jAbs(), WorkDir: work, MainClass: "-javaagent:x", AllowedRoots: []string{root}},
			"main-option-like",
		},
		{
			"entry-missing",
			ExternalJVMPlan{JavaExe: jAbs(), WorkDir: work, AllowedRoots: []string{root}},
			"entry-missing",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			audit := AuditExternalJVM(c.plan)
			if !findingHasCode(audit.Findings, c.want) {
				t.Fatalf("期望命中 %s，实际 codes=%v", c.want, audit.Findings)
			}
			if !audit.HasCritical() {
				t.Fatalf("应至少有一个 critical")
			}
		})
	}
}

func TestAuditExternalJVMAcceptsClasspathMode(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	work := filepath.Join(root, "install")
	cp1 := filepath.Join(work, "bootstrap.jar")
	cp2 := filepath.Join(root, "lib", "installer.jar")
	audit := AuditExternalJVM(ExternalJVMPlan{
		JavaExe:      javaExeForTest(),
		WorkDir:      work,
		Classpath:    []string{cp1, cp2},
		MainClass:    "com.bangbang93.ForgeInstaller",
		ProgramArgs:  []string{root},
		AllowedRoots: []string{root},
	})
	if audit.HasCritical() {
		t.Fatalf("classpath 主类模式应放行，得到 %s: %+v", audit.FirstCriticalCode(), audit.Findings)
	}
}

func TestAuditExternalJVMRejectsBadJava(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	work := filepath.Join(root, "bin")
	audit := AuditExternalJVM(ExternalJVMPlan{
		WorkDir:      work,
		JarAbsPath:   filepath.Join(work, "a.jar"),
		AllowedRoots: []string{root},
	})
	if !findingHasCode(audit.Findings, "java-empty") {
		t.Fatalf("缺少 java 时应命中 java-empty")
	}
}
