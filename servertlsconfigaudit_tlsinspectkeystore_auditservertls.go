package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func AuditServerTLS(serverDir string) TLSAudit {
	audit := TLSAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("", tlsReasonMissing, "服务器目录不存在", true)
		return audit
	}
	candidates := []string{"server.properties", "config/ssl.properties", "config/tls.properties"}
	present := false
	for _, rel := range candidates {
		path := filepath.Join(serverDir, rel)
		body, err := readBoundedFile(path, tlsMaxConfigBytes)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			audit.add(rel, tlsReasonUnreadable, "无法读取 TLS 配置", true)
			continue
		}
		present = true
		values := tlsParse(string(body))
		if protocols, ok := values["enabled-protocols"]; ok {
			if weak := tlsCfgWeakProtocol(protocols); weak != "" {
				audit.add(rel, tlsReasonWeakProtocol, fmt.Sprintf("启用弱协议 %s", weak), true)
			}
		}
		if protocols, ok := values["ssl-enabled-protocols"]; ok {
			if weak := tlsCfgWeakProtocol(protocols); weak != "" {
				audit.add(rel, tlsReasonWeakProtocol, fmt.Sprintf("启用弱协议 %s", weak), true)
			}
		}
		if ciphers, ok := values["cipher-suites"]; ok {
			if weak := tlsCfgWeakCipher(ciphers); weak != "" {
				audit.add(rel, tlsReasonWeakCipher, fmt.Sprintf("启用弱套件 %s", weak), true)
			}
		}
		for _, key := range []string{"keystore.path", "ssl.keystore", "key-store", "key-store-path", "truststore.path"} {
			if value, ok := values[key]; ok {
				tlsInspectKeystore(&audit, serverDir, rel+":"+key, value)
			}
		}
		for _, key := range []string{"keystore.password", "ssl.keystore.password", "key-store-password", "truststore.password"} {
			if value, ok := values[key]; ok && strings.TrimSpace(value) != "" {
				audit.add(rel, tlsReasonPlaintextPass, fmt.Sprintf("%s 以明文保存密钥库口令", key), true)
			}
		}
		if strings.EqualFold(values["ssl-enabled"], "true") && values["keystore.path"] == "" && values["key-store"] == "" {
			audit.add(rel, tlsReasonMissingKeystore, "启用 TLS 但未声明密钥库", true)
		}
	}
	entries, err := os.ReadDir(serverDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !tlsIsKeystore(entry.Name()) {
				continue
			}
			path := filepath.Join(serverDir, entry.Name())
			info, err := os.Lstat(path)
			if err != nil {
				audit.add(entry.Name(), tlsReasonUnreadable, "无法读取密钥库属性", true)
				continue
			}
			if info.Mode().Perm()&0o044 != 0 {
				audit.add(entry.Name(), tlsReasonWorldReadable, "密钥库对其他用户可读", true)
			}
		}
	}
	if !present && len(audit.Files) == 0 && len(audit.Findings) == 0 {
		audit.add("", tlsReasonOK, "未发现 TLS 配置", false)
	}
	if len(audit.Findings) == 0 {
		audit.add("", tlsReasonOK, "TLS 配置未发现风险", false)
	}
	return audit
}

type TLSAudit struct {
	Dir      string
	Files    []string
	Findings []TLSFinding
}
