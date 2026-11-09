package main

import (
	"fmt"
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
