package main

import (
	"archive/zip"
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
