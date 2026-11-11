package main

import (
	"archive/zip"
	"bytes"
	"fmt"
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

func (r *Log4ShellReport) add(sev JarFindingSeverity, rule, entry, detail string) {
	r.Findings = append(r.Findings, JarFinding{
		Rule:     rule,
		Severity: sev,
		Entry:    entry,
		Detail:   detail,
	})
}
func (r *Log4ShellReport) addOnce(sev JarFindingSeverity, rule, entry, detail string) {
	if r.findingSeen[rule] {
		return
	}
	r.findingSeen[rule] = true
	r.add(sev, rule, entry, detail)
}

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

type Log4ShellReport struct {
	Entries      int          `json:"entries"`
	ConfigFiles  int          `json:"configFiles"`
	Findings     []JarFinding `json:"findings"`
	findingSeen  map[string]bool
	limitEntries bool
	limitNested  bool
}

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
