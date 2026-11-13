package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *ServerSurfaceAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodes(a.Findings, func(f SurfaceFinding) string { return f.Reason })
}

func (a *ServerSurfaceAudit) Describe() string {
	if a == nil {
		return ""
	}
	if len(a.Findings) == 0 {
		return "服务器目录根层无可执行文件"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s): %s", f.Name, f.Reason, f.Detail))
	}
	return strings.Join(parts, "; ")
}

func AuditServerSurface(serverDir string) (*ServerSurfaceAudit, error) {
	audit := &ServerSurfaceAudit{Dir: serverDir}
	info, err := os.Lstat(serverDir)
	if err != nil {
		if os.IsNotExist(err) {
			return audit, nil
		}
		return nil, fmt.Errorf("读取服务器目录失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, SurfaceFinding{
			Name: filepath.Base(serverDir), Reason: surfaceReasonSymlink,
			Detail: "服务器目录本身是符号链接，根层审计结果不可信", Blocking: true,
		})
		return audit, nil
	}
	entries, err := os.ReadDir(serverDir)
	if err != nil {
		return nil, fmt.Errorf("读取服务器目录失败: %w", err)
	}
	if len(entries) > surfaceMaxEntries {
		audit.Findings = append(audit.Findings, SurfaceFinding{
			Name: filepath.Base(serverDir), Reason: surfaceReasonTooMany,
			Detail: fmt.Sprintf("根层条目 %d 个，超过 %d 上限", len(entries), surfaceMaxEntries), Blocking: true,
		})
		return audit, nil
	}
	for _, entry := range entries {
		audit.Entries++
		audit.auditEntry(serverDir, entry)
	}
	return audit, nil
}
