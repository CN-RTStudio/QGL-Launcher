package main

import (
	"archive/zip"
	"bytes"
	"fmt"
)

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
