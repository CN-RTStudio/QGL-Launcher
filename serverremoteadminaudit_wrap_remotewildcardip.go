package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func remoteWildcardIP(value string) bool {
	if ip := net.ParseIP(value); ip != nil {
		return ip.IsUnspecified()
	}
	for _, wildcard := range remoteWildcardBindings {
		if value == wildcard {
			return true
		}
	}
	return false
}

func (a *ServerRemoteAudit) Describe() string {
	if a == nil {
		return ""
	}
	if len(a.Findings) == 0 {
		return "server.properties 远程管理配置无风险"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s): %s", f.Key, f.Reason, f.Detail))
	}
	return strings.Join(parts, "; ")
}

func AuditServerRemoteAdmin(serverDir string) (*ServerRemoteAudit, error) {
	audit := &ServerRemoteAudit{
		Path:   filepath.Join(serverDir, "server.properties"),
		Values: map[string]string{},
	}
	info, err := os.Lstat(audit.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return audit, nil
		}
		return nil, fmt.Errorf("读取服务器配置失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Present = true
		audit.Findings = append(audit.Findings, RemoteFinding{
			Key: "server.properties", Reason: remoteReasonSymlink,
			Detail: "配置文件是符号链接，拒绝按远程管理配置审计", Blocking: true,
		})
		return audit, nil
	}
	if !info.Mode().IsRegular() {
		audit.Present = true
		audit.Findings = append(audit.Findings, RemoteFinding{
			Key: "server.properties", Reason: remoteReasonNotRegular,
			Detail: "配置文件不是普通文件", Blocking: true,
		})
		return audit, nil
	}
	if info.Size() > remoteMaxBytes {
		audit.Present = true
		audit.Findings = append(audit.Findings, RemoteFinding{
			Key: "server.properties", Reason: remoteReasonTooLarge,
			Detail: fmt.Sprintf("配置文件超过 %d 字节上限", remoteMaxBytes), Blocking: true,
		})
		return audit, nil
	}
	data, err := readBoundedFile(audit.Path, auditTextReadMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("读取服务器配置失败: %w", err)
	}
	audit.Present = true
	props := parseServerProperties(data)
	for _, key := range remoteKeys {
		if value, ok := props.Get(key); ok {
			audit.Values[key] = value
		}
	}
	for key, count := range remoteKeyCounts(data) {
		if count > 1 {
			audit.add(key, "", remoteReasonDuplicateKey,
				fmt.Sprintf("同一配置键出现 %d 次，生效值取决于解析顺序", count), false)
		}
	}
	audit.auditRcon(props)
	audit.auditQuery(props)
	audit.auditIdentity(props)
	audit.auditBinding(props)
	audit.auditLimits(props)
	return audit, nil
}
