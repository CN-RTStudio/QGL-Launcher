package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func AuditServerSettings(props *serverProperties) ServerSettingsAudit {
	audit := ServerSettingsAudit{}
	if props == nil {
		return audit
	}
	auditRconSettings(props, &audit)
	auditOnlineSettings(props, &audit)
	auditResourcePackSetting(props, &audit)
	return audit
}

func AuditServerSettingsFile(serverDir string) (ServerSettingsAudit, error) {
	path := filepath.Join(serverDir, "server.properties")
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ServerSettingsAudit{}, nil
		}
		return ServerSettingsAudit{}, fmt.Errorf("检查 server.properties 失败: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ServerSettingsAudit{}, fmt.Errorf("server.properties 不是普通文件，拒绝读取")
	}
	if info.Size() > worldProbeBytes {
		return ServerSettingsAudit{}, fmt.Errorf("server.properties 超过 %d 字节上限", worldProbeBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return ServerSettingsAudit{}, fmt.Errorf("打开 server.properties 失败: %v", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, worldProbeBytes+1))
	if err != nil {
		return ServerSettingsAudit{}, fmt.Errorf("读取 server.properties 失败: %v", err)
	}
	if len(raw) > worldProbeBytes {
		return ServerSettingsAudit{}, fmt.Errorf("server.properties 超过 %d 字节上限", worldProbeBytes)
	}
	return AuditServerSettings(parseServerProperties(raw)), nil
}
