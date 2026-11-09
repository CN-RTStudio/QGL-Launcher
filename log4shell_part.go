package main

import (
	"archive/zip"
	"io"
	"strings"
)

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
