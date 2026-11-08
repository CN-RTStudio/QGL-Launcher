package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	lgReasonOK             = "ok"
	lgReasonMissing        = "missing"
	lgReasonUnreadable     = "unreadable"
	lgReasonSymlink        = "symlink"
	lgReasonTooLarge       = "too-large"
	lgReasonJNDILookup     = "jndi-lookup"
	lgReasonEnvLookup      = "env-lookup"
	lgReasonPlainSecret    = "plaintext-secret"
	lgReasonWorldWritable  = "world-writable"
	lgReasonWorldReadable  = "world-readable"
	lgReasonRemoteAppender = "remote-appender"
	lgReasonJDBCTarget     = "jdbc-target"
	lgReasonLogSymlink     = "log-symlink"
	lgReasonLogRotate      = "log-rotate-missing"
	lgReasonLogVolume      = "log-volume"

	lgMaxConfigBytes = 2 << 20
	lgMaxLogBytes    = 256 << 20
	lgMaxLogFiles    = 64
	lgMaxFindings    = 64
)

var lgConfigCandidates = []string{
	"log4j2.xml",
	"log4j2-server.xml",
	"config/log4j2.xml",
	"logback.xml",
	"config/logback.xml",
	"logging.properties",
}

var lgSecretPatterns = []string{
	"password=",
	"password:",
	"<password>",
	"passwd=",
	"secret=",
	"accesskey",
	"secretkey",
	"apikey",
	"api_key",
}

var lgJNDITokens = []string{
	"${jndi:",
	"${jndi ",
	"jndilookup",
	"initialcontext",
}

var lgLookupTokens = []string{
	"${env:",
	"${sys:",
	"${ctx:",
	"${docker:",
	"${k8s:",
	"${date:",
	"${java:",
	"${lower:",
	"${upper:",
}

type LogConfigFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type LogConfigAudit struct {
	Dir      string
	Files    []string
	Findings []LogConfigFinding
}

func (a LogConfigAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a LogConfigAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != lgReasonOK {
			return true
		}
	}
	return false
}

func (a LogConfigAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == lgReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "log-config"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= lgMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务端日志配置未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *LogConfigAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= lgMaxFindings {
		return
	}
	a.Findings = append(a.Findings, LogConfigFinding{
		File:     file,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}

func lgScanConfigText(text string) (jndi, lookup, secret, remote, jdbc bool) {
	lower := strings.ToLower(text)
	for _, token := range lgJNDITokens {
		if strings.Contains(lower, token) {
			jndi = true
			break
		}
	}
	for _, token := range lgLookupTokens {
		if strings.Contains(lower, token) {
			lookup = true
			break
		}
	}
	for _, token := range lgSecretPatterns {
		if strings.Contains(lower, token) {
			secret = true
			break
		}
	}
	if strings.Contains(lower, "<socket") || strings.Contains(lower, "<jms") ||
		strings.Contains(lower, "syslog") || strings.Contains(lower, "httpappender") {
		remote = true
	}
	if strings.Contains(lower, "jdbc:") || strings.Contains(lower, "jdbcappender") {
		jdbc = true
	}
	return
}

func lgInspectConfig(a *LogConfigAudit, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	rel, relErr := filepath.Rel(a.Dir, path)
	if relErr != nil {
		rel = filepath.Base(path)
	}
	a.Files = append(a.Files, rel)
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(rel, lgReasonSymlink, "日志配置是符号链接", true)
		return
	}
	if info.Size() > lgMaxConfigBytes {
		a.add(rel, lgReasonTooLarge, "日志配置超过体积预算", true)
		return
	}
	if info.Mode().Perm()&0o022 != 0 {
		a.add(rel, lgReasonWorldWritable, "日志配置可被其他用户改写", true)
	}
	data, err := readBoundedFile(path, lgMaxConfigBytes)
	if err != nil {
		a.add(rel, lgReasonUnreadable, "日志配置不可读", true)
		return
	}
	jndi, lookup, secret, remote, jdbc := lgScanConfigText(string(data))
	if jndi {
		a.add(rel, lgReasonJNDILookup, "日志配置包含 JNDI 查找表达式", true)
	}
	if lookup {
		a.add(rel, lgReasonEnvLookup, "日志配置使用运行时属性查找", false)
	}
	if secret {
		a.add(rel, lgReasonPlainSecret, "日志配置内写了明文口令", true)
	}
	if remote {
		a.add(rel, lgReasonRemoteAppender, "日志配置存在远程 appender", true)
	}
	if jdbc {
		a.add(rel, lgReasonJDBCTarget, "日志配置直连数据库写入", false)
	}
}

func lgInspectLogDir(a *LogConfigAudit, dir string) {
	info, err := os.Lstat(dir)
	if err != nil {
		return
	}
	rel, relErr := filepath.Rel(a.Dir, dir)
	if relErr != nil {
		rel = "logs"
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(rel, lgReasonLogSymlink, "日志目录是符号链接", true)
		return
	}
	if !info.IsDir() {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add(rel, lgReasonUnreadable, "日志目录不可读", false)
		return
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		count++
		if count > lgMaxLogFiles {
			a.add(rel, lgReasonLogVolume, "日志目录文件数量超过预算", false)
			break
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		relFile := filepath.Join(rel, entry.Name())
		if info.Mode()&os.ModeSymlink != 0 {
			a.add(relFile, lgReasonSymlink, "日志文件是符号链接", true)
			continue
		}
		if info.Size() > lgMaxLogBytes {
			a.add(relFile, lgReasonTooLarge, "单个日志文件超过体积预算", false)
		}
		if info.Mode().Perm()&0o004 != 0 {
			a.add(relFile, lgReasonWorldReadable, "日志文件对其他用户可读", false)
		}
	}
	if count > 1 && !strings.Contains(strings.ToLower(strings.Join(lgFileNames(entries), ",")), ".gz") {
		a.add(rel, lgReasonLogRotate, "历史日志未压缩或未轮转", false)
	}
}

func lgFileNames(entries []os.DirEntry) []string {
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func AuditServerLogConfig(serverDir string) LogConfigAudit {
	audit := LogConfigAudit{Dir: serverDir}
	found := 0
	for _, rel := range lgConfigCandidates {
		path := filepath.Join(serverDir, rel)
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		found++
		lgInspectConfig(&audit, path)
	}
	if found == 0 {
		audit.add("log-config", lgReasonMissing, "未使用外部日志配置文件", false)
	}
	lgInspectLogDir(&audit, filepath.Join(serverDir, "logs"))
	if len(audit.Findings) == 0 {
		audit.add("log-config", lgReasonOK, "日志配置与日志目录符合预期", false)
	}
	return audit
}
