package main

import (
	"os"
	"path/filepath"
	"strings"
)

func jmxReadScript(serverDir, name string) ([]byte, string) {
	path := filepath.Join(serverDir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, jmxReasonMissing
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, jmxReasonSymlink
	}
	if !info.Mode().IsRegular() {
		return nil, jmxReasonUnreadable
	}
	if info.Size() > jmxMaxFileBytes {
		return nil, jmxReasonTooLarge
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return nil, jmxReasonUnreadable
	}
	return data, ""
}

func AuditServerJMX(serverDir string) JMXAudit {
	audit := JMXAudit{Dir: serverDir}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		audit.add("server", jmxReasonMissing, "服务器目录不存在", true)
		return audit
	}

	for i, name := range jmxScriptCandidates {
		if i >= jmxMaxScripts {
			break
		}
		data, reason := jmxReadScript(serverDir, name)
		if reason == jmxReasonMissing {
			continue
		}
		audit.Sources = append(audit.Sources, name)
		if reason != "" {
			audit.add(name, reason, "JMX 相关脚本不可用", reason == jmxReasonSymlink || reason == jmxReasonTooLarge)
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			jmxScanLine(&audit, name, line)
		}
	}

	for _, name := range jmxConfigCandidates {
		path := filepath.Join(serverDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		audit.Sources = append(audit.Sources, name)
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(name, jmxReasonSymlink, "JMX 管理配置是符号链接", true)
			continue
		}
		if !info.Mode().IsRegular() {
			audit.add(name, jmxReasonUnreadable, "JMX 管理配置不是普通文件", true)
			continue
		}
		if info.Size() > jmxMaxFileBytes {
			audit.add(name, jmxReasonTooLarge, "JMX 管理配置过大", true)
			continue
		}
		data, err := readBoundedFile(path, auditTextReadMaxBytes)
		if err != nil {
			audit.add(name, jmxReasonUnreadable, "JMX 管理配置不可读", true)
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			key, value, ok := jmxKeyValue(line)
			if !ok {
				continue
			}
			lower := strings.ToLower(key)
			switch {
			case lower == "com.sun.management.jmxremote.authenticate" && strings.EqualFold(value, "false"):
				audit.add(name, jmxReasonUnauthenticated, "管理配置文件关闭了 JMX 认证", true)
			case lower == "com.sun.management.jmxremote.ssl" && strings.EqualFold(value, "false"):
				audit.add(name, jmxReasonNoSSL, "管理配置文件关闭了 JMX TLS", true)
			case lower == "com.sun.management.jmxremote.port" && value != "" && value != "0":
				audit.add(name, jmxReasonBroadBind, "管理配置文件启用了 JMX 端口", true)
			case lower == "com.sun.management.jmxremote.password.file" && value != "":
				jmxCheckPasswordFile(&audit, serverDir, value, name)
			}
		}
	}

	if len(audit.Findings) == 0 {
		audit.add("", jmxReasonOK, "未启用 JMX 远程管理", false)
	}
	return audit
}
