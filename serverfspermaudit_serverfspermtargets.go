package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func serverFSPermTargets() []fsPermTarget {
	return []fsPermTarget{
		{Path: ".", Kind: "dir", BlockWrite: false, ExpectDir: true},
		{Path: "server.properties", Kind: "config", Secret: true, BlockWrite: true},
		{Path: "eula.txt", Kind: "config", BlockWrite: false},
		{Path: "ops.json", Kind: "config", Secret: true, BlockWrite: true},
		{Path: "whitelist.json", Kind: "config", Secret: true, BlockWrite: true},
		{Path: "banned-players.json", Kind: "config", BlockWrite: true},
		{Path: "banned-ips.json", Kind: "config", BlockWrite: true},
		{Path: "forwarding.secret", Kind: "secret", Secret: true, BlockWrite: true},
		{Path: "plugins", Kind: "dir", BlockWrite: true, ExpectDir: true},
		{Path: "logs", Kind: "dir", BlockWrite: false, ExpectDir: true},
		{Path: "world", Kind: "dir", BlockWrite: true, ExpectDir: true},
		{Path: "world/level.dat", Kind: "data", BlockWrite: true},
		{Path: "world/session.lock", Kind: "data", BlockWrite: false},
	}
}

func auditFSPermPath(audit *ServerFSPermAudit, serverDir string, target fsPermTarget) {
	path := filepath.Join(serverDir, target.Path)
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	audit.Checked = append(audit.Checked, target.Path)
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, FSPermFinding{Path: target.Path, Mode: mode.String(), Reason: fsPermReasonSymlink, Detail: "敏感路径是符号链接，实际目标不可信", Blocking: true})
		return
	}
	if target.ExpectDir && !info.IsDir() {
		audit.Findings = append(audit.Findings, FSPermFinding{Path: target.Path, Mode: mode.String(), Reason: fsPermReasonNotRegular, Detail: "期望目录但类型不符"})
		return
	}
	if !target.ExpectDir && !mode.IsRegular() && target.Kind != "dir" {
		audit.Findings = append(audit.Findings, FSPermFinding{Path: target.Path, Mode: mode.String(), Reason: fsPermReasonNotRegular, Detail: "期望常规文件但类型不符"})
		return
	}
	if runtime.GOOS == "windows" {
		audit.Findings = append(audit.Findings, FSPermFinding{Path: target.Path, Mode: mode.String(), Reason: fsPermReasonPlatform, Detail: "Windows 不使用 POSIX 权限位"})
		return
	}
	perm := mode.Perm()
	if perm&0o002 != 0 {
		audit.Findings = append(audit.Findings, FSPermFinding{
			Path:     target.Path,
			Mode:     fmt.Sprintf("%04o", perm),
			Reason:   fsPermReasonWorldWritable,
			Detail:   "同机任意账户可写，可被替换或篡改",
			Blocking: target.BlockWrite,
		})
	}
	if perm&0o020 != 0 && target.Secret {
		audit.Findings = append(audit.Findings, FSPermFinding{
			Path:     target.Path,
			Mode:     fmt.Sprintf("%04o", perm),
			Reason:   fsPermReasonGroupWritable,
			Detail:   "同组账户可写敏感配置",
			Blocking: false,
		})
	}
	if perm&0o044 != 0 && target.Secret {
		audit.Findings = append(audit.Findings, FSPermFinding{
			Path:     target.Path,
			Mode:     fmt.Sprintf("%04o", perm),
			Reason:   fsPermReasonWorldReadable,
			Detail:   "敏感内容包括凭据，可被其他账户读取",
			Blocking: false,
		})
	}
	if target.Kind == "config" && perm&0o111 != 0 {
		audit.Findings = append(audit.Findings, FSPermFinding{
			Path:     target.Path,
			Mode:     fmt.Sprintf("%04o", perm),
			Reason:   fsPermReasonExecutable,
			Detail:   "配置被标记为可执行，可能被误当作程序运行",
			Blocking: false,
		})
	}
	if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		audit.Findings = append(audit.Findings, FSPermFinding{
			Path:     target.Path,
			Mode:     mode.String(),
			Reason:   fsPermReasonSpecialBit,
			Detail:   "设置了 setuid/setgid/sticky 位",
			Blocking: false,
		})
	}
}

func AuditServerFSPermissions(serverDir string) *ServerFSPermAudit {
	audit := &ServerFSPermAudit{Dir: serverDir}
	if strings.TrimSpace(serverDir) == "" {
		audit.Findings = append(audit.Findings, FSPermFinding{Reason: fsPermReasonMissing, Detail: "未提供服务器目录"})
		return audit
	}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.Findings = append(audit.Findings, FSPermFinding{Reason: fsPermReasonMissing, Detail: "服务器目录不存在"})
		return audit
	}
	for _, target := range serverFSPermTargets() {
		auditFSPermPath(audit, serverDir, target)
	}
	if len(audit.Checked) == 0 {
		audit.Findings = append(audit.Findings, FSPermFinding{Reason: fsPermReasonMissing, Detail: "没有可审计的敏感路径"})
	}
	return audit
}
