package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func auditStartupFile(audit *ServerStartupAudit, dir, name string) {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	audit.Scripts = append(audit.Scripts, name)
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, StartupFinding{Script: name, Reason: startupReasonSymlink, Detail: "脚本是符号链接，内容不可信", Blocking: true})
		return
	}
	if !info.Mode().IsRegular() {
		audit.Findings = append(audit.Findings, StartupFinding{Script: name, Reason: startupReasonNotRegular, Detail: "不是常规文件", Blocking: false})
		return
	}
	if info.Size() > startupMaxBytes {
		audit.Findings = append(audit.Findings, StartupFinding{Script: name, Reason: startupReasonTooLarge, Detail: fmt.Sprintf("%d 字节超过上限", info.Size()), Blocking: false})
		return
	}
	data, err := readStartupScript(path)
	if err != nil {
		reason := startupReasonUnreadable
		if strings.Contains(err.Error(), "超过") {
			reason = startupReasonTooLarge
		}
		audit.Findings = append(audit.Findings, StartupFinding{Script: name, Reason: reason, Detail: truncateStartupLine(err.Error()), Blocking: false})
		return
	}
	lines := bytes.Split(data, []byte("\n"))
	for idx, raw := range lines {
		line := string(raw)
		if len(raw) > startupMaxLineBytes {
			line = truncateToRuneBoundary(raw, startupMaxLineBytes)
		}
		reason, detail, blocking, ok := classifyStartupLine(line)
		if ok {
			continue
		}
		if len(audit.Findings) >= startupMaxFindings {
			return
		}
		audit.Findings = append(audit.Findings, StartupFinding{
			Script:   name,
			Line:     idx + 1,
			Reason:   reason,
			Detail:   detail + ": " + truncateStartupLine(line),
			Blocking: blocking,
		})
	}
}
