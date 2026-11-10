package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	tlsReasonOK              = "ok"
	tlsReasonMissing         = "missing"
	tlsReasonUnreadable      = "unreadable"
	tlsReasonSymlink         = "symlink"
	tlsReasonWeakProtocol    = "weak-protocol"
	tlsReasonWeakCipher      = "weak-cipher"
	tlsReasonWorldReadable   = "world-readable-key"
	tlsReasonOutsideDir      = "key-outside-server"
	tlsReasonPlaintextPass   = "plaintext-keystore-password"
	tlsReasonMissingKeystore = "missing-keystore"
	tlsReasonBadKeystore     = "bad-keystore-path"
	tlsReasonTooLarge        = "keystore-too-large"

	tlsMaxKeystoreBytes = 32 << 20
	tlsMaxFindings      = 48
	tlsMaxConfigBytes   = 1 << 20
)

var tlsCfgWeakProtocols = []string{
	"sslv2",
	"sslv3",
	"tlsv1",
	"tlsv1.1",
	"ssl",
}

var tlsCfgWeakCiphers = []string{
	"null",
	"_rc4_",
	"rc4",
	"des_",
	"_des",
	"3des",
	"export",
	"anon",
	"_md5",
	"md5",
	"tls_rsa_with_des",
}

var tlsKeystoreExts = []string{".jks", ".p12", ".pfx", ".keystore"}

type TLSFinding struct {
	Key      string
	Reason   string
	Detail   string
	Blocking bool
}

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

func (a TLSAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f TLSFinding) bool { return f.Blocking })
}

func (a TLSAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f TLSFinding) bool { return !f.Blocking && f.Reason != tlsReasonOK })
}

func (a TLSAudit) Describe() string {
	return describeTaggedFindings("TLS 配置未发现风险", a.Findings, tlsReasonOK, "tls", tlsMaxFindings,
		func(f TLSFinding) string { return f.Reason },
		func(f TLSFinding) string { return f.Key },
		func(f TLSFinding) string { return f.Detail })
}

func (a *TLSAudit) add(key, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, tlsMaxFindings, TLSFinding{Key: key, Reason: reason, Detail: detail, Blocking: blocking})
}

func tlsParse(body string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		values[strings.TrimSpace(line[:eq])] = strings.TrimSpace(line[eq+1:])
	}
	return values
}
