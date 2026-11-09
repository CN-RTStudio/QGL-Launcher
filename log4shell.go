package main

import (
	"archive/zip"
	"bytes"
	"fmt"
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
