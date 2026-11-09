package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func auditStraySecretFile(audit *ServerStraySecretAudit, path, display string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	if len(audit.Scanned) >= strayMaxCandidates {
		return
	}
	audit.Scanned = append(audit.Scanned, display)
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, StraySecretFinding{Path: display, Reason: strayReasonSymlink, Detail: "候选凭据文件是符号链接", Blocking: true})
		return
	}
	if !info.Mode().IsRegular() {
		audit.Findings = append(audit.Findings, StraySecretFinding{Path: display, Reason: strayReasonNotRegular, Detail: "候选凭据路径不是常规文件"})
		return
	}
	if info.Size() > strayMaxFileBytes {
		audit.Findings = append(audit.Findings, StraySecretFinding{Path: display, Reason: strayReasonTooLarge, Detail: fmt.Sprintf("%d 字节超过扫描上限", info.Size())})
		return
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		audit.Findings = append(audit.Findings, StraySecretFinding{Path: display, Reason: strayReasonUnreadable, Detail: "文件不可读"})
		return
	}
	if len(data) > straySniffBytes {
		data = data[:straySniffBytes]
	}
	reason, detail, blocking := strayContentVerdict(data)
	if reason == "" {
		if info.Mode().Perm()&0o044 != 0 {
			audit.Findings = append(audit.Findings, StraySecretFinding{Path: display, Reason: strayReasonWorldReadable, Detail: "凭据文件对其他账户可读"})
		}
		lower := strings.ToLower(display)
		if strings.HasSuffix(lower, ".jks") || strings.HasSuffix(lower, ".p12") ||
			strings.HasSuffix(lower, ".pfx") || strings.Contains(lower, "keystore") {
			audit.Findings = append(audit.Findings, StraySecretFinding{Path: display, Reason: strayReasonKeystore, Detail: "密钥库文件可被直接复制使用"})
		}
		if !strings.HasPrefix(display, ".") && !strings.Contains(lower, "key") {
			audit.Findings = append(audit.Findings, StraySecretFinding{Path: display, Reason: strayReasonOK, Detail: "未发现明文凭据"})
		}
		return
	}
	audit.Findings = append(audit.Findings, StraySecretFinding{Path: display, Reason: reason, Detail: detail, Blocking: blocking})
}

func AuditServerStraySecrets(serverDir string) *ServerStraySecretAudit {
	audit := &ServerStraySecretAudit{Dir: serverDir}
	if strings.TrimSpace(serverDir) == "" {
		return audit
	}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		return audit
	}
	for _, rel := range straySecretDirs {
		dir := filepath.Join(serverDir, rel)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strayNameMatches(entry.Name()) {
				continue
			}
			if len(audit.Scanned) >= strayMaxCandidates {
				return audit
			}
			display := entry.Name()
			if rel != "." {
				display = filepath.Join(rel, entry.Name())
			}
			auditStraySecretFile(audit, filepath.Join(dir, entry.Name()), display)
		}
	}
	if len(audit.Scanned) == 0 {
		audit.Findings = append(audit.Findings, StraySecretFinding{Reason: strayReasonOK, Detail: "服务器目录没有候选凭据文件"})
	}
	return audit
}
