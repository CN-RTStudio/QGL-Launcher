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
