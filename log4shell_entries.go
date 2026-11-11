package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
)

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
