package main

import (
	"path/filepath"
	"strings"
)

const (
	// 这些上限按“宁大勿误杀”取值：正常启动参数远到不了，只在明显异常 / 疑似
	// 恶意构造时触发，绝不把正常游戏启动挡在门外。
	maxLaunchArgs         = 1024
	maxLaunchArgBytes     = 32 * 1024
	maxClasspathEntries   = 8192
	maxMainClassLen       = 1024
	maxPathLen            = 4096
	maxMemoryMBUpperBound = 1 << 20 // 1 TiB（1048576 MB）级 sanity，非功能性小上限
	minMemoryMBLowerBound = 8
)
const (
	launchSeverityCritical = "critical"
	launchSeverityWarn     = "warn"
	launchSeverityInfo     = "info"
)

type LaunchFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Field    string `json:"field"`
	Detail   string `json:"detail"`
}
type LaunchPlan struct {
	JavaExe      string   // java 可执行（绝对路径）
	WorkDir      string   // cmd.Dir 工作目录
	JarRelPath   string   // -jar 目标，必须是相对 WorkDir 的 .jar（与 MainClass 二选一）
	Classpath    []string // -classpath 各条目，相对 WorkDir
	MainClass    string   // 主类（无 -jar 时）
	ProgramArgs  []string // 主类之后传给游戏 / 服务器的参数
	MinMemoryMB  int      // -Xms
	MaxMemoryMB  int      // -Xmx
	AllowedRoots []string // WorkDir/jar/classpath 允许落在的根目录集合
}
type LaunchAudit struct {
	Findings []LaunchFinding `json:"findings"`
	Critical int             `json:"critical"`
	Warns    int             `json:"warns"`
}

func (a *LaunchAudit) add(code, severity, field, detail string) {
	a.Findings = append(a.Findings, LaunchFinding{
		Code: code, Severity: severity, Field: field, Detail: detail,
	})
	a.tallyOne(severity)
}
func (a *LaunchAudit) tally() {
	a.Critical, a.Warns = 0, 0
	for _, f := range a.Findings {
		a.tallyOne(f.Severity)
	}
}
func (a *LaunchAudit) tallyOne(severity string) {
	switch severity {
	case launchSeverityCritical:
		a.Critical++
	case launchSeverityWarn:
		a.Warns++
	}
}

func (a *LaunchAudit) HasCritical() bool { return a.Critical > 0 }

// FirstCriticalCode 返回第一条 critical 的稳定代码，无则空串，便于上层给出明确报错。
func (a *LaunchAudit) FirstCriticalCode() string {
	for _, f := range a.Findings {
		if f.Severity == launchSeverityCritical {
			return f.Code
		}
	}
	return ""
}

// hasTraversalSegment 报告路径按分隔符切分后是否出现独立的 ".." 段。
func hasTraversalSegment(p string) bool {
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}

// isUNC 报告路径是否为 Windows UNC 网络路径（\\host\share）。
func isUNC(p string) bool {
	return strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//")
}

// containedInAnyRoot 报告归一化后的目标是否落在任一允许根内（根自身也算）。
func containedInAnyRoot(target string, roots []string) bool {
	if len(roots) == 0 {
		return false
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	for _, root := range roots {
		if _, ok := PathWithin(root, absTarget); ok {
			return true
		}
	}
	return false
}

// auditJavaExe 校验 java 可执行路径：要求绝对、长度有界、非 UNC、无穿越、无控制符，
// Windows 上必须是 .exe（防止被指到脚本 / 批处理）。
