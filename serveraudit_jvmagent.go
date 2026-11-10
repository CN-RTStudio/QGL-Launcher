package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	jaReasonOK             = "ok"
	jaReasonMissing        = "missing"
	jaReasonUnreadable     = "unreadable"
	jaReasonSymlink        = "symlink"
	jaReasonAgentOutside   = "agent-outside-server"
	jaReasonAgentTraversal = "agent-traversal"
	jaReasonAgentMissing   = "agent-not-found"
	jaReasonBootClasspath  = "bootclasspath-override"
	jaReasonDebugAgent     = "debug-agent"
	jaReasonJMXOpen        = "jmx-unauthenticated"
	jaReasonSecurityMgr    = "security-manager-allow"
	jaReasonAgentLib       = "agentlib-injected"
	jaReasonTooLarge       = "too-large"

	jaMaxScriptBytes = 1 << 20
	jaMaxScripts     = 16
	jaMaxFindings    = 48
)

var jaScriptNames = []string{
	"start.sh",
	"start.bat",
	"start.cmd",
	"run.sh",
	"run.bat",
	"run.cmd",
	"launch.sh",
	"launch.bat",
	"user_jvm_args.txt",
	"args.txt",
	"jvm.args",
}

type JVMAgentFinding = auditFinding

type JVMAgentAudit struct {
	Dir      string
	Scripts  []string
	Findings []JVMAgentFinding
}

func (a JVMAgentAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JVMAgentFinding) bool { return f.Blocking })
}

func (a JVMAgentAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f JVMAgentFinding) bool { return !f.Blocking && f.Reason != jaReasonOK })
}

func jaAgentPath(token string) (string, bool) {
	for _, prefix := range []string{"-javaagent:", "-agentpath:"} {
		if strings.HasPrefix(token, prefix) {
			value := strings.TrimPrefix(token, prefix)
			if idx := strings.Index(value, "="); idx >= 0 {
				value = value[:idx]
			}
			return value, true
		}
	}
	return "", false
}
func jaCheckAgentPath(a *JVMAgentAudit, file, raw string) {
	path := strings.TrimSpace(strings.Trim(raw, `"`))
	if path == "" {
		a.add(file, jaReasonAgentMissing, "代理参数缺少路径", true)
		return
	}
	if strings.Contains(path, "..") {
		a.add(file, jaReasonAgentTraversal, "代理路径包含上级目录引用", true)
		return
	}
	resolved := path
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(a.Dir, resolved)
	}
	absDir, errDir := filepath.Abs(a.Dir)
	absFile, errFile := filepath.Abs(resolved)
	if errDir == nil && errFile == nil {
		rel, err := filepath.Rel(absDir, absFile)
		if err == nil && (rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			a.add(file, jaReasonAgentOutside, "代理 jar 位于服务器目录之外", true)
			return
		}
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		a.add(file, jaReasonAgentMissing, "代理 jar 不存在", false)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(file, jaReasonSymlink, "代理 jar 是符号链接", true)
	}
}

func jaInspectLine(a *JVMAgentAudit, file, line string) {
	for _, token := range jaSplitTokens(line) {
		if strings.HasPrefix(token, "#") {
			return
		}
		if path, ok := jaAgentPath(token); ok {
			jaCheckAgentPath(a, file, path)
			continue
		}
		lower := strings.ToLower(token)
		switch {
		case strings.HasPrefix(token, "-agentlib:"):
			value := strings.TrimPrefix(token, "-agentlib:")
			if strings.HasPrefix(strings.ToLower(value), "jdwp") {
				a.add(file, jaReasonDebugAgent, "开启 JDWP 调试代理", true)
				if strings.Contains(strings.ToLower(value), "address=*") ||
					strings.Contains(strings.ToLower(value), "address=0.0.0.0") {
					a.add(file, jaReasonDebugAgent, "调试代理监听全部接口", true)
				}
				continue
			}
			a.add(file, jaReasonAgentLib, "使用 agentlib 加载本地代理", false)
		case strings.HasPrefix(lower, "-xbootclasspath"):
			a.add(file, jaReasonBootClasspath, "覆盖引导类路径", true)
		case strings.HasPrefix(lower, "-djava.security.manager=allow"):
			a.add(file, jaReasonSecurityMgr, "允许运行时安装安全管理器", false)
		case strings.HasPrefix(lower, "-dcom.sun.management.jmxremote.authenticate=false"):
			a.add(file, jaReasonJMXOpen, "JMX 关闭认证", true)
		case strings.HasPrefix(lower, "-dcom.sun.management.jmxremote.port="):
			a.add(file, jaReasonJMXOpen, "开放 JMX 远程端口", false)
		}
	}
}

func jaInspectScript(a *JVMAgentAudit, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	rel, relErr := filepath.Rel(a.Dir, path)
	if relErr != nil {
		rel = filepath.Base(path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(rel, jaReasonSymlink, "启动脚本是符号链接", true)
		return
	}
	if info.Size() > jaMaxScriptBytes {
		a.add(rel, jaReasonTooLarge, "启动脚本超过体积预算", true)
		return
	}
	data, err := readBoundedFile(path, jaMaxScriptBytes)
	if err != nil {
		a.add(rel, jaReasonUnreadable, "启动脚本不可读", true)
		return
	}
	a.Scripts = append(a.Scripts, rel)
	for _, line := range strings.Split(string(data), "\n") {
		jaInspectLine(a, rel, strings.TrimSpace(line))
	}
}

func AuditServerJVMAgents(serverDir string) JVMAgentAudit {
	audit := JVMAgentAudit{Dir: serverDir}
	found := 0
	for _, name := range jaScriptNames {
		path := filepath.Join(serverDir, name)
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		if found >= jaMaxScripts {
			break
		}
		found++
		jaInspectScript(&audit, path)
	}
	if found == 0 {
		audit.add("jvm-args", jaReasonMissing, "未找到启动脚本或 JVM 参数文件", false)
	}
	if len(audit.Findings) == 0 {
		audit.add("jvm-args", jaReasonOK, "启动参数未包含代理注入", false)
	}
	return audit
}

func (a JVMAgentAudit) Describe() string {
	return describeTaggedFindings("JVM 启动参数未发现代理注入风险", a.Findings, jaReasonOK, "jvm-args", jaMaxFindings,
		func(f JVMAgentFinding) string { return f.Reason },
		func(f JVMAgentFinding) string { return f.File },
		func(f JVMAgentFinding) string { return f.Detail })
}
func (a *JVMAgentAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, jaMaxFindings, JVMAgentFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func jaSplitTokens(line string) []string {
	tokens := []string{}
	var current strings.Builder
	quote := rune(0)
	for _, r := range line {
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			current.WriteRune(r)
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == ' ' || r == '\t' || r == '\r' {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

const (
	sjaMaxFindings  = 28
	sjaMaxFile      = 64 * 1024
	sjaMaxHeapGB    = 32
	sjaReasonMiss   = "missing"
	sjaReasonLink   = "symlink"
	sjaReasonLarge  = "too-large"
	sjaReasonRead   = "unreadable"
	sjaReasonAgent  = "java-agent"
	sjaReasonBoot   = "bootclasspath"
	sjaReasonExec   = "on-error-command"
	sjaReasonArg    = "argfile-indirection"
	sjaReasonHeap   = "heap-too-large"
	sjaReasonPolicy = "security-manager"
	sjaReasonQuote  = "unbalanced-quote"
	sjaReasonCTRL   = "control-characters"
	sjaReasonJMX    = "jmx-exposed"
)

type JvmArgsFinding = auditFinding
type JvmArgsAudit struct {
	ServerDir string
	Findings  []JvmArgsFinding
}

func (a *JvmArgsAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sjaMaxFindings, JvmArgsFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *JvmArgsAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JvmArgsFinding) bool { return f.Blocking })
}

func (a *JvmArgsAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *JvmArgsAudit) Describe() string {
	return describeReasonDetail("user_jvm_args.txt 未发现风险", a.Findings, 12)
}

func sjaHeapGB(value string) (float64, bool) {
	upper := strings.ToUpper(strings.TrimSpace(value))
	mul := float64(1)
	switch {
	case strings.HasSuffix(upper, "G"):
		mul = 1
	case strings.HasSuffix(upper, "M"):
		mul = 1.0 / 1024.0
	case strings.HasSuffix(upper, "K"):
		mul = 1.0 / (1024.0 * 1024.0)
	default:
		return 0, false
	}
	number := strings.TrimSpace(upper[:len(upper)-1])
	v, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0, false
	}
	return v * mul, true
}

func AuditServerJvmArgsFile(serverDir string) *JvmArgsAudit {
	a := &JvmArgsAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("user_jvm_args.txt", sjaReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "user_jvm_args.txt"
	path := filepath.Join(serverDir, rel)
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, sjaReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, sjaReasonLink, "JVM 参数文件是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, sjaReasonMiss, "未找到 user_jvm_args.txt", false)
		return a
	}
	data, err := readBoundedFile(path, sjaMaxFile)
	if err != nil {
		reason := sjaReasonRead
		if err == errLocalFileTooLarge {
			reason = sjaReasonLarge
		}
		a.add(rel, reason, err.Error(), true)
		return a
	}
	text := string(data)
	tokens := strings.Fields(strings.ReplaceAll(text, "\r\n", "\n"))
	quoteOpen := false
	for _, token := range tokens {
		if strings.HasPrefix(token, "#") {
			continue
		}
		if strings.Count(token, "\"")%2 == 1 {
			quoteOpen = !quoteOpen
		}
		lower := strings.ToLower(token)
		switch {
		case strings.HasPrefix(lower, "-javaagent:"):
			a.add(rel, sjaReasonAgent, token, true)
		case strings.HasPrefix(lower, "-agentlib:"):
			a.add(rel, sjaReasonAgent, token, true)
		case strings.HasPrefix(lower, "-agentpath:"):
			a.add(rel, sjaReasonAgent, token, true)
		case strings.HasPrefix(lower, "-xbootclasspath"):
			a.add(rel, sjaReasonBoot, token, true)
		case strings.HasPrefix(lower, "-xx:onerror"), strings.HasPrefix(lower, "-xx:onoutofmemoryerror"):
			a.add(rel, sjaReasonExec, token, true)
		case strings.HasPrefix(lower, "@"):
			a.add(rel, sjaReasonArg, token, true)
		case strings.Contains(lower, "java.security.manager=allow"):
			a.add(rel, sjaReasonPolicy, token, false)
		case strings.Contains(lower, "com.sun.management.jmxremote"):
			if !strings.Contains(lower, "authenticate=true") && !strings.Contains(lower, "ssl=true") {
				a.add(rel, sjaReasonJMX, token, false)
			}
		case strings.HasPrefix(lower, "-xmx") || strings.HasPrefix(lower, "-xms"):
			if gb, ok := sjaHeapGB(token[4:]); ok && gb > sjaMaxHeapGB {
				a.add(rel, sjaReasonHeap, token, false)
			}
		}
		if cfgHasControlChars(token) {
			a.add(rel, sjaReasonCTRL, "参数含控制字符", true)
		}
	}
	if quoteOpen {
		a.add(rel, sjaReasonQuote, "引号未闭合", true)
	}
	return a
}

const (
	ljMaxFindings      = 48
	ljMaxConfig        = 512 * 1024
	ljMaxJarName       = 128
	ljVulnVersion      = "2.17.0"
	ljReasonOK         = "ok"
	ljReasonMissing    = "missing"
	ljReasonVulnerable = "vulnerable-log4j"
	ljReasonJndiLookup = "jndi-lookup"
	ljReasonPattern    = "forced-lookup-pattern"
	ljReasonBadConfig  = "bad-config"
	ljReasonSymlink    = "symlink"
	ljReasonTooLarge   = "too-large"
	ljReasonBadName    = "bad-jar-name"
)

type Log4jFinding = auditFinding
type Log4jShellAudit struct {
	ServerDir string
	Jars      int
	Configs   int
	Findings  []Log4jFinding
}

func (a *Log4jShellAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, ljMaxFindings, Log4jFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *Log4jShellAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f Log4jFinding) bool { return f.Blocking })
}
func (a *Log4jShellAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f Log4jFinding) bool { return f.Reason != ljReasonOK && !f.Blocking })
}
func (a *Log4jShellAudit) Describe() string {
	return describeFindings(a.Findings, func(f Log4jFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func ljStripJarName(name string) (string, string) {
	base := strings.ToLower(filepath.Base(name))
	if !strings.HasSuffix(base, ".jar") {
		return "", ""
	}
	base = strings.TrimSuffix(base, ".jar")
	if !strings.HasPrefix(base, "log4j-core-") {
		return "", ""
	}
	version := strings.TrimPrefix(base, "log4j-core-")
	if version == "" {
		return "", ""
	}
	return base, version
}

func ljParseVersion(raw string) (int, int, int, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return 0, 0, 0, false
	}
	nums := make([]int, 0, 3)
	for i := 0; i < 3 && i < len(parts); i++ {
		chunk := parts[i]
		if i == 2 {
			idx := strings.IndexAny(chunk, "-+")
			if idx >= 0 {
				chunk = chunk[:idx]
			}
			if chunk == "" {
				chunk = "0"
			}
		}
		n, err := strconv.Atoi(chunk)
		if err != nil || n < 0 {
			return 0, 0, 0, false
		}
		nums = append(nums, n)
	}
	for len(nums) < 3 {
		nums = append(nums, 0)
	}
	return nums[0], nums[1], nums[2], true
}

func ljVersionVulnerable(major, minor int) bool {
	if major != 2 {
		return major == 1
	}
	return minor < 17
}

func ljScanJarDir(root, rel string, a *Log4jShellAudit) {
	dir := filepath.Join(root, rel)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return
	}
	_ = filepath.Walk(dir, func(path string, fi os.FileInfo, werr error) error {
		if werr != nil {
			return nil
		}
		if fi.IsDir() {
			return nil
		}
		relPath, rerr := filepath.Rel(root, path)
		if rerr != nil {
			relPath = path
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			a.add(relPath, ljReasonSymlink, "日志组件路径为符号链接", true)
			return nil
		}
		if len(filepath.Base(path)) > ljMaxJarName {
			a.add(relPath, ljReasonBadName, "文件名超长", false)
			return nil
		}
		base, version := ljStripJarName(path)
		if base == "" {
			return nil
		}
		a.Jars++
		major, minor, patch, ok := ljParseVersion(version)
		if !ok {
			a.add(relPath, ljReasonBadName, "版本号无法解析: "+version, false)
			return nil
		}
		if ljVersionVulnerable(major, minor) {
			a.add(relPath, ljReasonVulnerable, fmt.Sprintf("log4j-core %d.%d.%d 低于 %s", major, minor, patch, ljVulnVersion), true)
		}
		return nil
	})
}

func ljScanConfig(root string, a *Log4jShellAudit) {
	for _, rel := range []string{"log4j2.xml", "config/log4j2.xml"} {
		path := filepath.Join(root, rel)
		sym, serr := isSymlinkOrSpecial(path)
		if serr == nil && sym {
			a.add(rel, ljReasonSymlink, "配置文件为符号链接或特殊文件", true)
			continue
		}
		data, err := readBoundedFile(path, ljMaxConfig)
		if err != nil {
			if _, serr := os.Lstat(path); serr == nil {
				if strings.Contains(err.Error(), "too large") {
					a.add(rel, ljReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", ljMaxConfig), true)
				}
			}
			continue
		}
		a.Configs++
		text := strings.ToLower(string(data))
		if !strings.Contains(text, "log4j") && !strings.Contains(text, "appenders") {
			a.add(rel, ljReasonBadConfig, "内容不像 log4j2 配置", false)
			continue
		}
		if strings.Contains(text, "${jndi:") || strings.Contains(text, "%{jndi:") {
			a.add(rel, ljReasonJndiLookup, "配置中出现 JNDI 查找表达式", true)
		}
		if strings.Contains(text, "${ctx:") || strings.Contains(text, "$${") {
			a.add(rel, ljReasonPattern, "配置中出现强制查找占位符", false)
		}
		if strings.Contains(text, "<lookup") || strings.Contains(text, "lookups=") {
			a.add(rel, ljReasonPattern, "配置显式声明 lookup 扩展", true)
		}
	}
}

func AuditServerLog4jShell(serverDir string) *Log4jShellAudit {
	a := &Log4jShellAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", ljReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", ljReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", ljReasonMissing, "服务器目录不存在", false)
		return a
	}
	ljScanJarDir(serverDir, "libraries", a)
	ljScanJarDir(serverDir, "plugins", a)
	ljScanConfig(serverDir, a)
	if a.Jars == 0 && a.Configs == 0 {
		a.add(".", ljReasonMissing, "未发现 log4j 组件与配置", false)
	}
	return a
}
