package main

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
		JavaExe:      jAbs(),
		WorkDir:      workDir,
		MinMemoryMB:  1024,
		MaxMemoryMB:  4096,
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
