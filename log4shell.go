package main

// log4shell.go —— 针对 Log4Shell（CVE-2021-44228 等一系列 log4j2 JNDI 注入）与
// “主动外联 JNDI”的静态内容扫描，在 Mod jar 落进 mods 目录前执行。
//
// 背景：Minecraft 与大量 Mod 长期自带 Apache log4j2。2.0-beta7 ~ 2.14.x 的
// JndiLookup 会把日志文本里的 ${jndi:ldap://...} 解析成一次真正的 JNDI 远程
// 类加载，攻击者只要让受害者记下一段聊天文本即可 RCE。即便主程序已升级，
// 某个 Mod 用 JarJar 把旧版 log4j-core 一起打进来，隐患依旧存在。
//
// 这里只做只读静态扫描，绝不执行 / 不解压落地：
//
//   - jar 内存在 JndiLookup.class（org/apache/logging/log4j/core/lookup/
//     JndiLookup.class，含 JarJar 内层）：强烈提示携带了未移除该类的旧版
//     log4j-core，critical 阻断，要求换成 2.17.1+（或 2.12.4+/2.3.2+）；
//   - 任意 log4j2 配置 / 文本资源出现 ${jndi: 字面量：critical；
//   - class 常量池同时引用 javax.naming.InitialContext 与 ldap/rmi/dns 等
//     JNDI 子协议：具备主动外联 JNDI 的能力，warn（合法 Mod 极少需要）；
//   - 配置里显式打开 message lookups（%m{lookups} / lookups=true）：warn。
//
// 与 jarscan.go 的区别：jarscan 面向“通用恶意形态”（代理 / 根可执行 / 类加载
// 挂钩），本文件只专注 Log4Shell / JNDI 这一类有明确 CVE 与 IOC 的威胁。

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
)

const (
	// log4jMaxEntries 限制参与扫描的条目数，防海量条目耗尽 CPU。
	log4jMaxEntries = 50000
	// log4jTextCap 限制单个配置 / 文本条目最多读取字节数。
	log4jTextCap = 1 << 20 // 1 MiB
	// log4jMaxClasses 限制参与常量池分析的 class 条数。
	log4jMaxClasses = 3000
	// log4jClassCap 限制单个 class 读取字节数。
	log4jClassCap = 1 << 20 // 1 MiB
	// log4jClassBytesCap 限制所有 class 累计读取字节数。
	log4jClassBytesCap = 16 << 20 // 16 MiB
	// log4jNestedDepth 是嵌套 jar 递归扫描的最大深度（外层记为第 1 层）。
	log4jNestedDepth = 2
	// log4jMaxNested 限制参与递归的嵌套 jar 数量。
	log4jMaxNested = 32
	// log4jNestedBytesCap 限制嵌套 jar 累计读取字节数。
	log4jNestedBytesCap = 64 << 20 // 64 MiB
	// log4jPerNestedCap 限制单个嵌套 jar 读取字节数。
	log4jPerNestedCap = 8 << 20 // 8 MiB
)

// Log4ShellReport 是一次 Log4Shell / JNDI 扫描的结果。
type Log4ShellReport struct {
	Entries      int          `json:"entries"`
	ConfigFiles  int          `json:"configFiles"`
	Findings     []JarFinding `json:"findings"`
	findingSeen  map[string]bool
	limitEntries bool
	limitNested  bool
}

// Blocked 报告是否存在必须阻断的 critical 发现。
func (r *Log4ShellReport) Blocked() bool {
	if r == nil {
		return false
	}
	for _, f := range r.Findings {
		if f.Severity == JarSeverityCritical {
			return true
		}
	}
	return false
}

func (r *Log4ShellReport) add(sev JarFindingSeverity, rule, entry, detail string) {
	r.Findings = append(r.Findings, JarFinding{
		Rule:     rule,
		Severity: sev,
		Entry:    entry,
		Detail:   detail,
	})
}

// addOnce 对同一规则只记录一次（跨成百个 class / 嵌套 jar 去重）。
func (r *Log4ShellReport) addOnce(sev JarFindingSeverity, rule, entry, detail string) {
	if r.findingSeen[rule] {
		return
	}
	r.findingSeen[rule] = true
	r.add(sev, rule, entry, detail)
}

// 易受攻击版本携带的 JNDI 查询类，路径大小写敏感（包名固定小写），
// 但做前缀匹配以兼容 JarJar 内层前缀。
const log4jJndiLookupSuffix = "org/apache/logging/log4j/core/lookup/jndilookup.class"

// 认为是 log4j2 配置的扩展名（小写，含点）。
var log4jConfigExts = map[string]bool{
	".xml": true, ".properties": true, ".yaml": true, ".yml": true, ".json": true,
}

// 除配置外，也扫描这些纯文本资源里的 ${jndi: 字面量（攻击载荷可能藏在数据文件）。
var log4jTextExts = map[string]bool{
	".txt": true, ".log": true, ".cfg": true, ".conf": true, ".toml": true,
}

// JNDI 子协议：出现在 class 常量池里通常意味着“会发起远程 JNDI”。
var jndiUrlSchemes = []string{"ldap://", "ldaps://", "rmi://", "dns://", "corbaname:", "iiop://"}

// scanLog4ShellBytes 对内存中的 jar 字节做扫描（便于测试直接构造 zip）。
func scanLog4ShellBytes(data []byte) (*Log4ShellReport, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("不是有效的 jar/zip 文件: %v", err)
	}
	return scanLog4ShellReader(zr), nil
}

// scanLog4ShellJar 扫描磁盘上的 jar；只读、不执行、不解压落地。
func scanLog4ShellJar(jarPath string) (*Log4ShellReport, error) {
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return nil, fmt.Errorf("打开 jar 失败: %v", err)
	}
	defer zr.Close()
	return scanLog4ShellReader(&zr.Reader), nil
}

func scanLog4ShellReader(zr *zip.Reader) *Log4ShellReport {
	rep := &Log4ShellReport{Findings: []JarFinding{}, findingSeen: map[string]bool{}}
	nestedCount, nestedBytes := 0, 0
	scanLog4ShellInto(rep, zr, 1, "", &nestedCount, &nestedBytes)
	if rep.limitEntries {
		rep.add(JarSeverityInfo, "log4j-scan-limit", "",
			fmt.Sprintf("条目数超过 %d，仅扫描了前 %d 条", log4jMaxEntries, rep.Entries))
	}
	if rep.limitNested {
		rep.add(JarSeverityInfo, "log4j-nested-limit", "",
			fmt.Sprintf("嵌套 jar 深度/数量/体积超限（%d 层 / %d 个），部分未展开",
				log4jNestedDepth, log4jMaxNested))
	}
	return rep
}

// scanLog4ShellInto 扫描单个 zip 层级，prefix 为嵌套 jar 的展示前缀。
func scanLog4ShellInto(rep *Log4ShellReport, zr *zip.Reader, depth int, prefix string,
	nestedCount *int, nestedBytes *int) {
	classSeen, classBytes := 0, 0

	for i, f := range zr.File {
		if i >= log4jMaxEntries {
			rep.limitEntries = true
			break
		}
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if name == "" {
			continue
		}
		rep.Entries++
		lower := strings.ToLower(name)
		display := prefix + name
		ext := pathExtLower(lower)

		// 1) 携带 JndiLookup.class：未移除该类的旧版 log4j-core，critical。
		if strings.HasSuffix(lower, log4jJndiLookupSuffix) {
			rep.add(JarSeverityCritical, "jndi-lookup-class", display,
				"jar 内存在 log4j JndiLookup 类，提示携带 Log4Shell 影响版本（log4j-core 2.14 及更早），应升级到 2.17.1+ / 2.12.4+ / 2.3.2+")
		}

		// 2) 嵌套 jar 递归（旧 log4j 常被 JarJar 打进内层）。
		if ext == ".jar" {
			scanLog4ShellNested(rep, f, display, depth, nestedCount, nestedBytes)
		}

		isConfig := isLog4jConfigEntry(lower, ext)
		if isConfig {
			rep.ConfigFiles++
		}
		scanText := isConfig || log4jTextExts[ext]

		// 3) 配置 / 文本资源：${jndi: 字面量、显式开启 lookups。
		if scanText && f.FileInfo().Mode().IsRegular() {
			text := readBoundedZipText(f, log4jTextCap)
			if text != "" {
				inspectLog4jText(rep, display, text, isConfig)
			}
		}

		// 4) class 常量池：InitialContext + JNDI 子协议的主动外联能力。
		if ext == ".class" && classSeen < log4jMaxClasses && classBytes < log4jClassBytesCap {
			if n := inspectLog4jClass(rep, f, display, classBytes); n > 0 {
				classBytes += n
				classSeen++
			}
		}
	}
}

// isLog4jConfigEntry 判定条目是否是 log4j2 配置：
// 文件名是 log4j2.* 且在受支持的扩展名内，或位于 META-INF 且以 log4j 开头。
func isLog4jConfigEntry(lower, ext string) bool {
	if !log4jConfigExts[ext] {
		return false
	}
	base := lower
	if idx := strings.LastIndexByte(lower, '/'); idx >= 0 {
		base = lower[idx+1:]
	}
	if strings.HasPrefix(base, "log4j2") || strings.HasPrefix(base, "log4j-test") {
		return true
	}
	return strings.HasPrefix(lower, "meta-inf/") && strings.HasPrefix(base, "log4j")
}

// readBoundedZipText 读取文本条目（有字节上限），统一转小写并折叠换行；
// 解码失败时返回空串（跳过而不是误报）。
func readBoundedZipText(f *zip.File, cap int64) string {
	rc, err := f.Open()
	if err != nil {
		return ""
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, cap))
	if err != nil || len(data) == 0 {
		return ""
	}
	return strings.ToLower(string(data))
}

// inspectLog4jText 在配置 / 文本里查找 Log4Shell IOC。
func inspectLog4jText(rep *Log4ShellReport, entry, text string, isConfig bool) {
	if strings.Contains(text, "${jndi:") || strings.Contains(text, "${jndi :") {
		// 配置文件里写死 JNDI lookup 几乎必为恶意/隐患；普通数据文件降级为 warn。
		if isConfig {
			rep.add(JarSeverityCritical, "jndi-literal-config", entry,
				"log4j2 配置包含 ${jndi: 查找表达式，可被用于 Log4Shell 远程代码执行")
		} else {
			rep.add(JarSeverityWarn, "jndi-literal-resource", entry,
				"资源文本包含 ${jndi: 载荷字面量，若会被记录进存在漏洞的 log4j 日志可触发 RCE")
		}
	}
	if isConfig && containsMessageLookupEnable(text) {
		rep.add(JarSeverityWarn, "message-lookup-enabled", entry,
			"log4j2 配置显式开启 message lookups（%m{lookups} / lookups=true），旧版本会解析日志文本里的 ${...}")
	}
}

// containsMessageLookupEnable 识别“打开消息查找”的常见配置写法。
func containsMessageLookupEnable(lowerText string) bool {
	if strings.Contains(lowerText, "%m{lookups}") || strings.Contains(lowerText, "%msg{lookups}") ||
		strings.Contains(lowerText, "%message{lookups}") {
		return true
	}
	// <PatternLayout ... lookups="true"> / isLookups=true 等属性写法。
	if strings.Contains(lowerText, "lookups") && strings.Contains(lowerText, "true") {
		return true
	}
	return false
}

// inspectLog4jClass 只解析 class 常量池 UTF8，判断是否“JNDI 命名上下文 + 远程
// 子协议”同时出现。绝不加载 / 验证 / 执行字节码。
func inspectLog4jClass(rep *Log4ShellReport, f *zip.File, entry string, spent int) int {
	rc, err := f.Open()
	if err != nil {
		return 0
	}
	defer rc.Close()

	left := log4jClassBytesCap - spent
	limit := int64(log4jClassCap)
	if int64(left) < limit {
		limit = int64(left)
	}
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil || len(data) == 0 {
		return 0
	}
	texts := classConstantPoolUTF8(data)
	if texts == nil {
		return 0 // 魔数不符 / 结构截断，跳过
	}

	hasNaming := false
	hasJndiUrl := false
	hasLookupClassRef := false
	for _, s := range texts {
		ls := strings.ToLower(s)
		if !hasNaming && (strings.Contains(ls, "javax/naming/initialcontext") ||
			strings.Contains(ls, "javax/naming/context")) {
			hasNaming = true
		}
		if !hasJndiUrl {
			for _, scheme := range jndiUrlSchemes {
				if strings.Contains(ls, scheme) {
					hasJndiUrl = true
					break
				}
			}
		}
		if !hasLookupClassRef && strings.Contains(ls, "log4j/core/lookup/") {
			hasLookupClassRef = true
		}
	}
	if hasNaming && hasJndiUrl {
		rep.addOnce(JarSeverityWarn, "jndi-outbound-class", entry,
			"class 常量池同时引用 javax.naming 与 ldap/rmi/dns 子协议，具备主动外联 JNDI（远程类加载）能力")
	}
	if hasLookupClassRef && hasJndiUrl {
		rep.addOnce(JarSeverityWarn, "log4j-jndi-url", entry,
			"class 常量池出现 log4j lookup 引用与 JNDI 子协议 URL，需确认是否为受影响 log4j 版本")
	}
	return len(data)
}

// scanLog4ShellNested 在有界预算内递归扫描嵌套 jar。
func scanLog4ShellNested(rep *Log4ShellReport, f *zip.File, display string, depth int,
	nestedCount *int, nestedBytes *int) {
	if depth >= log4jNestedDepth {
		rep.limitNested = true
		return
	}
	if *nestedCount >= log4jMaxNested || *nestedBytes >= log4jNestedBytesCap {
		rep.limitNested = true
		return
	}
	rc, err := f.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	left := log4jNestedBytesCap - *nestedBytes
	limit := int64(log4jPerNestedCap)
	if int64(left) < limit {
		limit = int64(left)
	}
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil || len(data) == 0 {
		return
	}
	childZr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		// 非合法 zip（损坏 / 伪装）不致命：jarscan 已有 nested-unreadable 告警。
		return
	}
	*nestedCount++
	*nestedBytes += len(data)
	scanLog4ShellInto(rep, childZr, depth+1, display+"!/", nestedCount, nestedBytes)
}

// enforceLog4ShellScan 是 Mod 安装链上的 Log4Shell 专用入口：扫描磁盘 jar，
// 把每条发现写入安全审计日志，出现 critical 返回错误（调用方负责删除临时
// 文件 / 终止导入）。
func enforceLog4ShellScan(jarPath, source, label string) (*Log4ShellReport, error) {
	rep, err := scanLog4ShellJar(jarPath)
	if err != nil {
		recordSecurityEvent(auditCategoryLog4Shell, auditSeverityCritical, auditActionBlocked,
			source, "log4j 扫描无法解析 jar，拒绝安装: "+sanitizeLogLine(label))
		return nil, err
	}

	critical := 0
	for _, f := range rep.Findings {
		action := auditActionDetected
		if f.Severity == JarSeverityCritical {
			action = auditActionBlocked
			critical++
		}
		detail := fmt.Sprintf("[%s] %s %s", f.Rule, f.Entry, f.Detail)
		recordSecurityEvent(auditCategoryLog4Shell, string(f.Severity), action, source,
			sanitizeLogLine(detail))
	}

	if critical > 0 {
		return rep, fmt.Errorf("Mod jar 命中 %d 个 Log4Shell/JNDI 高危项，已阻止安装: %s",
			critical, sanitizeLogLine(label))
	}
	return rep, nil
}
