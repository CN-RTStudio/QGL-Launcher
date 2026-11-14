package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
			detail = fmt.Sprintf("%s，首个命中行: %s", detail, sanitizeLogLine(line))
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
