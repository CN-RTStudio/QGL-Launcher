package main

import (
	"fmt"
	"path/filepath"
	"runtime"
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
func auditJavaExe(exe string) []LaunchFinding {
	var out []LaunchFinding
	if strings.TrimSpace(exe) == "" {
		return append(out, LaunchFinding{"java-empty", launchSeverityCritical, "javaExe", "java 可执行路径为空"})
	}
	if len(exe) > maxPathLen {
		out = append(out, LaunchFinding{"java-long", launchSeverityCritical, "javaExe", "java 可执行路径过长"})
	}
	if containsControlByte(exe) {
		out = append(out, LaunchFinding{"java-control", launchSeverityCritical, "javaExe", "java 可执行路径含控制字符"})
	}
	if isUNC(exe) {
		out = append(out, LaunchFinding{"java-unc", launchSeverityCritical, "javaExe", "不允许使用网络共享上的 java"})
	}
	if !filepath.IsAbs(exe) {
		out = append(out, LaunchFinding{"java-not-absolute", launchSeverityCritical, "javaExe", "java 可执行必须是绝对路径"})
	}
	if hasTraversalSegment(exe) {
		out = append(out, LaunchFinding{"java-traversal", launchSeverityCritical, "javaExe", "java 可执行路径含目录穿越段"})
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(exe), ".exe") {
		out = append(out, LaunchFinding{"java-not-exe", launchSeverityCritical, "javaExe", "Windows 上 java 启动器必须是 .exe"})
	}
	return out
}

// auditWorkDir 校验工作目录：绝对、有界、非 UNC、无穿越、且落在允许根集合内。
func auditWorkDir(dir string, roots []string) []LaunchFinding {
	var out []LaunchFinding
	if strings.TrimSpace(dir) == "" {
		return append(out, LaunchFinding{"workdir-empty", launchSeverityCritical, "workDir", "工作目录为空"})
	}
	if len(dir) > maxPathLen {
		out = append(out, LaunchFinding{"workdir-long", launchSeverityCritical, "workDir", "工作目录路径过长"})
	}
	if containsControlByte(dir) {
		out = append(out, LaunchFinding{"workdir-control", launchSeverityCritical, "workDir", "工作目录含控制字符"})
	}
	if isUNC(dir) {
		out = append(out, LaunchFinding{"workdir-unc", launchSeverityCritical, "workDir", "不允许把网络共享作为工作目录"})
	}
	if !filepath.IsAbs(dir) {
		out = append(out, LaunchFinding{"workdir-not-absolute", launchSeverityCritical, "workDir", "工作目录必须是绝对路径"})
	}
	if hasTraversalSegment(dir) {
		out = append(out, LaunchFinding{"workdir-traversal", launchSeverityCritical, "workDir", "工作目录含目录穿越段"})
	}
	if !containedInAnyRoot(dir, roots) {
		out = append(out, LaunchFinding{"workdir-outside", launchSeverityCritical, "workDir", "工作目录不在允许的安装根内"})
	}
	return out
}

// auditJarRelPath 校验 -jar 目标。它必须是相对 WorkDir 的单个 .jar 文件名（或含
// 子目录但不得逃逸），禁止绝对路径与 ".." 段；解析后必须仍在 WorkDir 与允许根内。
func auditJarRelPath(workDir, jar string, roots []string) []LaunchFinding {
	var out []LaunchFinding
	if strings.TrimSpace(jar) == "" {
		return out // 未使用 -jar（主类模式）时为空，合法。
	}
	if len(jar) > maxPathLen {
		return append(out, LaunchFinding{"jar-long", launchSeverityCritical, "jar", "jar 路径过长"})
	}
	if containsControlByte(jar) {
		return append(out, LaunchFinding{"jar-control", launchSeverityCritical, "jar", "jar 路径含控制字符"})
	}
	if filepath.IsAbs(jar) || isUNC(jar) {
		return append(out, LaunchFinding{"jar-absolute", launchSeverityCritical, "jar", "jar 目标必须是相对工作目录的路径"})
	}
	if hasTraversalSegment(jar) {
		return append(out, LaunchFinding{"jar-traversal", launchSeverityCritical, "jar", "jar 目标含目录穿越段"})
	}
	if !strings.EqualFold(filepath.Ext(jar), ".jar") {
		return append(out, LaunchFinding{"jar-not-jar", launchSeverityCritical, "jar", "-jar 目标必须以 .jar 结尾"})
	}
	joined := filepath.Join(workDir, jar)
	if _, ok := PathWithin(workDir, joined); !ok {
		out = append(out, LaunchFinding{"jar-escapes-workdir", launchSeverityCritical, "jar", "jar 解析后逃逸出工作目录"})
	}
	if !containedInAnyRoot(joined, roots) {
		out = append(out, LaunchFinding{"jar-outside-root", launchSeverityCritical, "jar", "jar 解析后不在允许的安装根内"})
	}
	return out
}

// auditClasspath 校验 -classpath 各条目：数量有界、非空（空条目=当前目录）、相对
// WorkDir、无穿越，解析后仍在允许根内。
func auditClasspath(workDir string, entries []string, roots []string) []LaunchFinding {
	var out []LaunchFinding
	if len(entries) > maxClasspathEntries {
		return append(out, LaunchFinding{"cp-too-many", launchSeverityCritical, "classpath", "classpath 条目过多"})
	}
	for i, entry := range entries {
		field := fmt.Sprintf("classpath[%d]", i)
		if entry == "" {
			out = append(out, LaunchFinding{"cp-empty", launchSeverityCritical, field, "classpath 含空条目（等同当前目录）"})
			continue
		}
		if len(entry) > maxPathLen {
			out = append(out, LaunchFinding{"cp-long", launchSeverityCritical, field, "classpath 条目过长"})
			continue
		}
		if containsControlByte(entry) {
			out = append(out, LaunchFinding{"cp-control", launchSeverityCritical, field, "classpath 条目含控制字符"})
			continue
		}
		if filepath.IsAbs(entry) || isUNC(entry) {
			out = append(out, LaunchFinding{"cp-absolute", launchSeverityCritical, field, "classpath 条目必须相对工作目录"})
			continue
		}
		if hasTraversalSegment(entry) {
			out = append(out, LaunchFinding{"cp-traversal", launchSeverityCritical, field, "classpath 条目含目录穿越段"})
			continue
		}
		joined := filepath.Join(workDir, entry)
		if _, inWork := PathWithin(workDir, joined); !inWork || !containedInAnyRoot(joined, roots) {
			out = append(out, LaunchFinding{"cp-outside", launchSeverityCritical, field, "classpath 条目逃逸出允许目录"})
		}
	}
	return out
}

// auditMainClass 校验主类标识：允许 a.b.C 形式，或 module/a.b.C 形式；拒前导 '-'
// （伪装 JVM 选项）、空白、控制符与非法字符。
func auditMainClass(mainClass string) []LaunchFinding {
	var out []LaunchFinding
	if strings.TrimSpace(mainClass) == "" {
		return out // -jar 模式下为空，合法。
	}
	if len(mainClass) > maxMainClassLen {
		return append(out, LaunchFinding{"main-long", launchSeverityCritical, "mainClass", "主类名过长"})
	}
	if containsControlByte(mainClass) || strings.ContainsAny(mainClass, " \t") {
		return append(out, LaunchFinding{"main-control", launchSeverityCritical, "mainClass", "主类名含空白或控制字符"})
	}
	if strings.HasPrefix(mainClass, "-") || strings.HasPrefix(mainClass, "@") {
		return append(out, LaunchFinding{"main-option-like", launchSeverityCritical, "mainClass", "主类名形似 JVM 选项或 argfile"})
	}
	cls := mainClass
	if idx := strings.Index(mainClass, "/"); idx >= 0 {
		cls = mainClass[idx+1:] // 丢掉可选的 module/ 前缀，仅校验类名部分
	}
	if cls == "" {
		return append(out, LaunchFinding{"main-empty-class", launchSeverityCritical, "mainClass", "缺少类名部分"})
	}
	for _, seg := range strings.Split(cls, ".") {
		if seg == "" {
			return append(out, LaunchFinding{"main-empty-segment", launchSeverityCritical, "mainClass", "主类名含空段"})
		}
		if !isJavaIdentSegment(seg) {
			return append(out, LaunchFinding{"main-bad-char", launchSeverityCritical, "mainClass", "主类名含非法字符"})
		}
	}
	return out
}

// isJavaIdentSegment 校验主类名中的一段是否为合法 Java 标识（允许内部类的 '$'）。
func isJavaIdentSegment(seg string) bool {
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$' {
			continue
		}
		return false
	}
	return true
}

// auditProgramArgs 只做“有界 + 无控制字符”校验：主类之后的参数会原样传给游戏 /
// 服务器 main，JVM 不再解析，因此 --username/-x 等都是合法的，不能按 JVM 选项拦。
func auditProgramArgs(args []string) []LaunchFinding {
	var out []LaunchFinding
	if len(args) > maxLaunchArgs {
		return append(out, LaunchFinding{"args-too-many", launchSeverityCritical, "programArgs", "程序参数数量过多"})
	}
	for i, arg := range args {
		field := fmt.Sprintf("programArgs[%d]", i)
		if len(arg) > maxLaunchArgBytes {
			out = append(out, LaunchFinding{"arg-long", launchSeverityCritical, field, "单个程序参数过长"})
			continue
		}
		if containsControlByte(arg) {
			out = append(out, LaunchFinding{"arg-control", launchSeverityCritical, field, "程序参数含控制字符"})
		}
	}
	return out
}

// auditMemory 校验堆内存边界：正整数、下限 sanity、min 不得大于 max、设一个极大的
// 上限仅用于拦截荒谬 / 溢出值，不做会误杀正常配置的小上限。
func auditMemory(minMB, maxMB int) []LaunchFinding {
	var out []LaunchFinding
	if minMB < minMemoryMBLowerBound {
		out = append(out, LaunchFinding{"mem-min-small", launchSeverityCritical, "minMemory", "最小堆内存小于可启动下限"})
	}
	if maxMB < minMemoryMBLowerBound {
		out = append(out, LaunchFinding{"mem-max-small", launchSeverityCritical, "maxMemory", "最大堆内存小于可启动下限"})
	}
	if minMB > 0 && maxMB > 0 && minMB > maxMB {
		out = append(out, LaunchFinding{"mem-order", launchSeverityCritical, "memory", "最小堆内存大于最大堆内存"})
	}
	if maxMB > maxMemoryMBUpperBound {
		out = append(out, LaunchFinding{"mem-max-huge", launchSeverityWarn, "maxMemory", "最大堆内存超过合理上限"})
	}
	return out
}

// AuditLaunchPlan 聚合审计一整份启动目标计划，返回所有结论。
func AuditLaunchPlan(plan LaunchPlan) *LaunchAudit {
	a := &LaunchAudit{}
	a.Findings = append(a.Findings, auditJavaExe(plan.JavaExe)...)
	a.Findings = append(a.Findings, auditWorkDir(plan.WorkDir, plan.AllowedRoots)...)
	a.Findings = append(a.Findings, auditJarRelPath(plan.WorkDir, plan.JarRelPath, plan.AllowedRoots)...)
	a.Findings = append(a.Findings, auditClasspath(plan.WorkDir, plan.Classpath, plan.AllowedRoots)...)
	a.Findings = append(a.Findings, auditMainClass(plan.MainClass)...)
	a.Findings = append(a.Findings, auditProgramArgs(plan.ProgramArgs)...)
	a.Findings = append(a.Findings, auditMemory(plan.MinMemoryMB, plan.MaxMemoryMB)...)
	// -jar 与主类必须二选一：两者都空等于没有启动入口；两者都给会造成调用歧义。
	// 这里直接 append 而不调用 add：所有结论统一由下方循环计数，避免重复累加。
	if strings.TrimSpace(plan.JarRelPath) == "" && strings.TrimSpace(plan.MainClass) == "" {
		a.Findings = append(a.Findings, LaunchFinding{"entry-missing", launchSeverityCritical, "entry", "必须指定 -jar 目标或主类之一"})
	}
	if strings.TrimSpace(plan.JarRelPath) != "" && strings.TrimSpace(plan.MainClass) != "" {
		a.Findings = append(a.Findings, LaunchFinding{"entry-ambiguous", launchSeverityWarn, "entry", "同时给出了 -jar 与主类，以 -jar 为准"})
	}
	a.tally()
	return a
}

// AuditServerLaunch 是 StartServer 的便捷封装：服务器固定用
// "<version>-server.jar" 且 jar 位于 ServerDir。Java 可执行由
// SelectJavaForVersion 单独保证，此处不重复审计 java，只校验工作目录、由版本名
// 拼出的 jar 是否会逃逸、以及内存边界。
func AuditServerLaunch(serverDir, version string, minMB, maxMB int, roots []string) *LaunchAudit {
	jar := ""
	if v := strings.TrimSpace(version); v != "" {
		jar = v + "-server.jar"
	}
	a := &LaunchAudit{}
	a.Findings = append(a.Findings, auditWorkDir(serverDir, roots)...)
	a.Findings = append(a.Findings, auditJarRelPath(serverDir, jar, roots)...)
	a.Findings = append(a.Findings, auditMemory(minMB, maxMB)...)
	if strings.TrimSpace(jar) == "" {
		a.Findings = append(a.Findings, LaunchFinding{"entry-missing", launchSeverityCritical, "entry", "版本名为空，无法定位 -jar 目标"})
	}
	a.tally()
	return a
}

// auditAbsJar 校验一个“绝对路径”的 -jar 目标：必须绝对、.jar、无穿越/控制符，且落在
// 任一允许根内。安装器（Forge/OptiFine/下载的第三方安装器）的 jar 往往位于 mcDir 或
// 临时目录，不能套用 auditJarRelPath 的“必须相对工作目录”规则。
func auditAbsJar(target string, roots []string) []LaunchFinding {
	var out []LaunchFinding
	if strings.TrimSpace(target) == "" {
		return out // 主类模式时空，合法
	}
	if len(target) > maxPathLen {
		return append(out, LaunchFinding{"absjar-long", launchSeverityCritical, "jar", "jar 路径过长"})
	}
	if containsControlByte(target) {
		return append(out, LaunchFinding{"absjar-control", launchSeverityCritical, "jar", "jar 路径含控制字符"})
	}
	if isUNC(target) {
		return append(out, LaunchFinding{"absjar-unc", launchSeverityCritical, "jar", "不允许运行网络共享上的 jar"})
	}
	if !filepath.IsAbs(target) {
		return append(out, LaunchFinding{"absjar-not-absolute", launchSeverityCritical, "jar", "安装器 jar 必须是绝对路径"})
	}
	if hasTraversalSegment(target) {
		return append(out, LaunchFinding{"absjar-traversal", launchSeverityCritical, "jar", "jar 路径含目录穿越段"})
	}
	if !strings.EqualFold(filepath.Ext(target), ".jar") {
		return append(out, LaunchFinding{"absjar-not-jar", launchSeverityCritical, "jar", "运行目标必须以 .jar 结尾"})
	}
	if !containedInAnyRoot(target, roots) {
		return append(out, LaunchFinding{"absjar-outside", launchSeverityCritical, "jar", "jar 不在允许的目录集合内"})
	}
	return out
}

// auditAbsClasspath 校验绝对路径形式的 -classpath 各条目：数量有界、绝对、.jar、无
// 穿越/控制符、落在允许根集合内。
func auditAbsClasspath(entries []string, roots []string) []LaunchFinding {
	var out []LaunchFinding
	if len(entries) > maxClasspathEntries {
		return append(out, LaunchFinding{"abscp-too-many", launchSeverityCritical, "classpath", "classpath 条目过多"})
	}
	for i, entry := range entries {
		field := fmt.Sprintf("classpath[%d]", i)
		if entry == "" {
			out = append(out, LaunchFinding{"abscp-empty", launchSeverityCritical, field, "classpath 含空条目（等同当前目录）"})
			continue
		}
		if len(entry) > maxPathLen {
			out = append(out, LaunchFinding{"abscp-long", launchSeverityCritical, field, "classpath 条目过长"})
			continue
		}
		if containsControlByte(entry) {
			out = append(out, LaunchFinding{"abscp-control", launchSeverityCritical, field, "classpath 条目含控制字符"})
			continue
		}
		if isUNC(entry) {
			out = append(out, LaunchFinding{"abscp-unc", launchSeverityCritical, field, "不允许把网络共享加入 classpath"})
			continue
		}
		if !filepath.IsAbs(entry) {
			out = append(out, LaunchFinding{"abscp-not-absolute", launchSeverityCritical, field, "安装器 classpath 必须是绝对路径"})
			continue
		}
		if hasTraversalSegment(entry) {
			out = append(out, LaunchFinding{"abscp-traversal", launchSeverityCritical, field, "classpath 条目含目录穿越段"})
			continue
		}
		if !strings.EqualFold(filepath.Ext(entry), ".jar") {
			out = append(out, LaunchFinding{"abscp-not-jar", launchSeverityCritical, field, "classpath 条目必须以 .jar 结尾"})
			continue
		}
		if !containedInAnyRoot(entry, roots) {
			out = append(out, LaunchFinding{"abscp-outside", launchSeverityCritical, field, "classpath 条目逃逸出允许目录"})
		}
	}
	return out
}

// ExternalJVMPlan 描述“运行外部安装器 JVM”需要审计的各段。与 LaunchPlan 的区别：
// Jar/Classpath 允许绝对路径，但必须落在显式给出的 AllowedRoots 内。
type ExternalJVMPlan struct {
	JavaExe      string
	WorkDir      string
	JarAbsPath   string   // -jar 绝对目标（与 MainClass 二选一）
	Classpath    []string // 绝对路径 .jar 集合
	MainClass    string
	ProgramArgs  []string
	AllowedRoots []string
}

// AuditExternalJVM 审计安装器 / 第三方 jar 的 JVM 启动：java 可执行、工作目录、
// 绝对 jar / classpath 的目录归属、主类与程序参数。任一 critical 都应阻止启动。
func AuditExternalJVM(plan ExternalJVMPlan) *LaunchAudit {
	a := &LaunchAudit{}
	a.Findings = append(a.Findings, auditJavaExe(plan.JavaExe)...)
	a.Findings = append(a.Findings, auditWorkDir(plan.WorkDir, plan.AllowedRoots)...)
	a.Findings = append(a.Findings, auditAbsJar(plan.JarAbsPath, plan.AllowedRoots)...)
	a.Findings = append(a.Findings, auditAbsClasspath(plan.Classpath, plan.AllowedRoots)...)
	a.Findings = append(a.Findings, auditMainClass(plan.MainClass)...)
	a.Findings = append(a.Findings, auditProgramArgs(plan.ProgramArgs)...)
	if strings.TrimSpace(plan.JarAbsPath) == "" && strings.TrimSpace(plan.MainClass) == "" {
		a.Findings = append(a.Findings, LaunchFinding{"entry-missing", launchSeverityCritical, "entry", "必须指定 -jar 目标或主类之一"})
	}
	if strings.TrimSpace(plan.JarAbsPath) != "" && strings.TrimSpace(plan.MainClass) != "" {
		a.Findings = append(a.Findings, LaunchFinding{"entry-ambiguous", launchSeverityWarn, "entry", "同时给出了 -jar 与主类"})
	}
	a.tally()
	return a
}
