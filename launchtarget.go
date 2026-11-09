package main

import (
	"path/filepath"
	"strings"
)

// launchtarget.go —— JVM「启动目标」与位置参数安全审计内核。
//
// 威胁模型：
//   jvmargs.go（r22，@argfile 收敛）解决的是“JVM 选项”这一段（-Xmx/-javaagent
//   等）。但一次 exec.Command 里还有几段同样可被版本清单 / 服务器配置 / 整合包
//   描述文件影响，历史上没有统一校验：
//     1) java 可执行路径：被换成 UNC、含穿越段或控制字符的路径；
//     2) cmd.Dir 工作目录：逃逸到安装根之外，让相对路径解析落到攻击者目录；
//     3) -jar 目标：StartServer 直接用 cfg.Version 拼 "<v>-server.jar"，若版本名
//        含 "/"、".." 或绝对前缀，可让 JVM 加载工作目录之外的任意 jar（=RCE）；
//     4) -classpath：清单里的库拼进 classpath，空条目等于当前目录，穿越条目可把
//        攻击者目录塞进类搜索路径；
//     5) 主类名：塞入前导 '-' 伪装成 JVM 选项，或塞入空白 / 控制字符；
//     6) 程序参数（主类之后）：数量 / 长度 / 控制字符无界，畸形值可触发下游解析缺陷；
//     7) 内存参数：min>max、负值或荒谬值导致 JVM 直接启动失败（可用性）。
//
//   本模块只做纯判定：输入 -> Findings，绝不启动进程、不触碰文件系统（containment
//   全部走字符串 / filepath 归一化）。是否存在、是否常规文件由调用方结合 os.Stat
//   决定，避免把“文件必须存在”的策略和“路径必须安全”的判定耦合在一起。

const (
	// 这些上限按“宁大勿误杀”取值：正常启动参数远到不了，只在明显异常 / 疑似
	// 恶意构造时触发，绝不把正常游戏启动挡在门外。
	maxLaunchArgs          = 1024
	maxLaunchArgBytes      = 32 * 1024
	maxClasspathEntries    = 8192
	maxMainClassLen        = 1024
	maxPathLen             = 4096
	maxMemoryMBUpperBound  = 1 << 20 // 1 TiB（1048576 MB）级 sanity，非功能性小上限
	minMemoryMBLowerBound  = 8
)

// 审计结论严重级别：critical 必须阻断启动；warn 记录但可继续；info 仅提示。
const (
	launchSeverityCritical = "critical"
	launchSeverityWarn     = "warn"
	launchSeverityInfo     = "info"
)

// LaunchFinding 是单条审计结论。Code 稳定可用于测试与上层本地化，Field 指明
// 出错的启动字段，Detail 只放中性描述，绝不回显完整可疑输入。
type LaunchFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Field    string `json:"field"`
	Detail   string `json:"detail"`
}

// LaunchPlan 描述一次 JVM 启动中“除 JVM 选项外”需要审计的各段。JVMOptions 已由
// jvmargs 内核单独收敛，本结构不重复审计，只要求调用方确实做过分离。
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

// LaunchAudit 聚合一次启动目标审计的全部结论。
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

// tally 重新统计全部 findings 的级别计数。审计函数都是先 append 结论、最后统一
// 调用它，避免在多处分散维护计数而漏算 / 重算。
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

// HasCritical 报告是否存在必须阻断启动的结论。
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
