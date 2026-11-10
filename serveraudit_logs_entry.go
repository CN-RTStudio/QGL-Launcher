package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (a *ServerLogAudit) auditLogEntry(dir string, entry os.DirEntry) {
	name := entry.Name()
	if len([]rune(name)) > serverLogMaxNameRunes || containsControlByte(name) {
		a.Findings = append(a.Findings, LogFinding{
			Name: name, Reason: logAuditReasonBadName, Detail: "日志文件名含控制字符或超长",
		})
	}
	info, err := os.Lstat(filepath.Join(dir, name))
	if err != nil {
		a.Findings = append(a.Findings, LogFinding{
			Name: name, Reason: logAuditReasonUnreadable, Detail: "无法读取日志文件属性",
		})
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.Findings = append(a.Findings, LogFinding{
			Name: name, Reason: logAuditReasonSymlink,
			Detail: "日志文件是符号链接，写入会落到服务器目录之外", Blocking: true,
		})
		return
	}
	if !info.Mode().IsRegular() {
		a.Findings = append(a.Findings, LogFinding{
			Name: name, Reason: logAuditReasonNotRegular, Detail: "日志条目不是普通文件", Blocking: true,
		})
		return
	}
	if info.Size() > serverLogMaxFileBytes {
		a.Findings = append(a.Findings, LogFinding{
			Name: name, Reason: logAuditReasonTooLarge,
			Detail: fmt.Sprintf("日志大小 %d 字节，超过 %d 上限", info.Size(), serverLogMaxFileBytes),
		})
	}
}

func (a *ServerLogAudit) auditLatestLog(path string) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	if info.Size() > serverLogMaxFileBytes {
		return
	}
	if info.Size() > serverLogScanBytes {
		a.Findings = append(a.Findings, LogFinding{
			Name: "latest.log", Reason: logAuditReasonScanTooLarge,
			Detail: fmt.Sprintf("latest.log 大小 %d 字节，仅扫描前 %d 字节", info.Size(), serverLogScanBytes),
		})
	}
	data, err := readLogHead(path, serverLogScanBytes)
	if err != nil {
		return
	}
	lower := bytes.ToLower(data)
	for _, marker := range logExploitMarkers {
		if !bytes.Contains(lower, []byte(marker)) {
			continue
		}
		line := findLogLineWithMarker(data, marker)
		detail := fmt.Sprintf("latest.log 含 %q 利用特征（可能是 Log4Shell/JNDI 注入尝试）", marker)
		if line != "" {
			detail = fmt.Sprintf("%s，首个命中行: %s", detail, line)
		}
		a.Findings = append(a.Findings, LogFinding{
			Name: "latest.log", Reason: logAuditReasonExploitMark, Detail: detail,
		})
	}
}

func readLogHead(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, int64(limit)))
}

func findLogLineWithMarker(data []byte, marker string) string {
	lines := bytes.Split(data, []byte("\n"))
	for _, raw := range lines {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		if strings.Contains(strings.ToLower(line), marker) {
			return truncateLogLine(line, 160)
		}
	}
	return ""
}

func truncateLogLine(line string, max int) string {
	if len([]rune(line)) <= max {
		return line
	}
	runes := []rune(line)
	return string(runes[:max]) + "..."
}

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

type LogConfigFinding = auditFinding
type LogConfigAudit struct {
	Dir      string
	Files    []string
	Findings []LogConfigFinding
}

func (a LogConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f LogConfigFinding) bool { return f.Blocking })
}
func (a LogConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f LogConfigFinding) bool { return !f.Blocking && f.Reason != lgReasonOK })
}

func (a LogConfigAudit) Describe() string {
	return describeTaggedFindings("服务端日志配置未发现风险", a.Findings, lgReasonOK, "log-config", lgMaxFindings,
		func(f LogConfigFinding) string { return f.Reason },
		func(f LogConfigFinding) string { return f.File },
		func(f LogConfigFinding) string { return f.Detail })
}
func (a *LogConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, lgMaxFindings, LogConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
