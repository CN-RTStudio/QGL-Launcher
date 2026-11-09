package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func readStartupScript(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, startupMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > startupMaxBytes {
		return nil, fmt.Errorf("脚本超过 %d 字节", startupMaxBytes)
	}
	return data, nil
}

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
			line = string(raw[:startupMaxLineBytes])
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

func AuditServerStartupScripts(serverDir string) *ServerStartupAudit {
	audit := &ServerStartupAudit{Dir: serverDir}
	if strings.TrimSpace(serverDir) == "" {
		audit.Findings = append(audit.Findings, StartupFinding{Script: "", Reason: startupReasonMissing, Detail: "未提供服务器目录"})
		return audit
	}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.Findings = append(audit.Findings, StartupFinding{Script: "", Reason: startupReasonMissing, Detail: "服务器目录不存在"})
		return audit
	}
	for _, name := range startupScriptNames {
		auditStartupFile(audit, serverDir, name)
	}
	if len(audit.Scripts) == 0 {
		audit.Findings = append(audit.Findings, StartupFinding{Script: "", Reason: startupReasonMissing, Detail: "未找到启动脚本"})
	}
	return audit
}
