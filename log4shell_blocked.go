package main

import (
	"archive/zip"
	"strings"
)

func (r *Log4ShellReport) Blocked() bool {
	if r == nil {
		return false
	}
	return anyBlocking(r.Findings, func(f JarFinding) bool { return f.Severity == JarSeverityCritical })
}

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
