package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func tlsCfgWeakProtocol(value string) string {
	lower := strings.ToLower(value)
	for _, weak := range tlsCfgWeakProtocols {
		if strings.Contains(lower, weak) {
			return weak
		}
	}
	return ""
}

func tlsCfgWeakCipher(value string) string {
	lower := strings.ToLower(value)
	for _, weak := range tlsCfgWeakCiphers {
		if strings.Contains(lower, weak) {
			return weak
		}
	}
	return ""
}

func tlsIsKeystore(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range tlsKeystoreExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func tlsInspectKeystore(audit *TLSAudit, serverDir, key, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if strings.Contains(value, "..") {
		audit.add(key, tlsReasonBadKeystore, "密钥库路径包含上级目录引用", true)
		return
	}
	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(serverDir, value)
	}
	absServer, err := filepath.Abs(serverDir)
	if err != nil {
		audit.add(key, tlsReasonUnreadable, "无法解析服务器目录", true)
		return
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		audit.add(key, tlsReasonBadKeystore, "密钥库路径非法", true)
		return
	}
	if !strings.HasPrefix(absPath, absServer+string(os.PathSeparator)) {
		audit.add(key, tlsReasonOutsideDir, fmt.Sprintf("密钥库位于服务器目录之外: %s", value), true)
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		audit.add(key, tlsReasonMissingKeystore, "声明的密钥库文件不存在", true)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(key, tlsReasonSymlink, "密钥库是符号链接", true)
		return
	}
	if info.Size() > tlsMaxKeystoreBytes {
		audit.add(key, tlsReasonTooLarge, "密钥库体积超过预算", true)
		return
	}
	if info.Mode().Perm()&0o044 != 0 {
		audit.add(key, tlsReasonWorldReadable, "密钥库对其他用户可读", true)
	}
	audit.Files = append(audit.Files, value)
}
