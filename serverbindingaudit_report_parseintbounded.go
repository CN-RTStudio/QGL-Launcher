package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func parseIntBounded(value string, min, max int) (int, bool) {
	if value == "" {
		return 0, false
	}
	negative := false
	start := 0
	if value[0] == '-' {
		negative = true
		start = 1
	}
	if start >= len(value) {
		return 0, false
	}
	n := 0
	for i := start; i < len(value); i++ {
		ch := value[i]
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n*10 + int(ch-'0')
		if n > 1<<30 {
			return 0, false
		}
	}
	if negative {
		n = -n
	}
	if n < min || n > max {
		return n, false
	}
	return n, true
}

func (a *ServerBindingAudit) Describe() string {
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == bindingReasonOK {
			continue
		}
		if f.Key != "" {
			parts = append(parts, fmt.Sprintf("%s=%q(%s): %s", f.Key, f.Value, f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s", f.Reason, f.Detail))
	}
	return strings.Join(parts, "；")
}

func AuditServerBinding(serverDir string) (*ServerBindingAudit, error) {
	path := filepath.Join(serverDir, "server.properties")
	audit := &ServerBindingAudit{Path: path}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			audit.Findings = append(audit.Findings, BindingFinding{
				Reason: bindingReasonMissing, Detail: "server.properties 不存在，无法审计网络暴露策略",
			})
			return audit, nil
		}
		return nil, fmt.Errorf("读取 server.properties 属性失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, BindingFinding{
			Reason: bindingReasonSymlink, Detail: "server.properties 是符号链接，可能指向服务器目录之外",
			Blocking: true,
		})
		return audit, nil
	}
	if !info.Mode().IsRegular() {
		audit.Findings = append(audit.Findings, BindingFinding{
			Reason: bindingReasonUnreadable, Detail: "server.properties 不是普通文件", Blocking: true,
		})
		return audit, nil
	}
	if info.Size() > int64(localTextConfigMaxBytes) {
		audit.Findings = append(audit.Findings, BindingFinding{
			Reason:   bindingReasonTooLarge,
			Detail:   fmt.Sprintf("server.properties 大小 %d 字节，超过 %d 上限", info.Size(), localTextConfigMaxBytes),
			Blocking: true,
		})
		return audit, nil
	}
	data, err := readBoundedFile(path, int64(localTextConfigMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("读取 server.properties 失败: %w", err)
	}
	props := parseServerProperties(data)
	audit.Present = true

	audit.auditOnlineMode(props)
	audit.auditBindAddress(props)
	audit.auditSecureProfile(props)
	audit.auditProxyConnections(props)
	audit.auditStatus(props)
	audit.auditNumericLimits(props)
	return audit, nil
}
