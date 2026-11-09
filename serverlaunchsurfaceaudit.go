package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	surfaceReasonOK         = "ok"
	surfaceReasonSymlink    = "symlink"
	surfaceReasonNotRegular = "not-regular"
	surfaceReasonExecutable = "executable"
	surfaceReasonExtraJar   = "extra-jar"
	surfaceReasonBadName    = "bad-name"
	surfaceReasonTooMany    = "too-many"
	surfaceReasonUnreadable = "unreadable"

	surfaceMaxEntries   = 2048
	surfaceMaxNameRunes = 128
)

var surfaceExecutableExts = []string{
	".exe", ".scr", ".com", ".pif", ".msi", ".bat", ".cmd",
	".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".sh",
}

type SurfaceFinding struct {
	Name     string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerSurfaceAudit struct {
	Dir      string
	Entries  int
	Findings []SurfaceFinding
}

func (a *ServerSurfaceAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f SurfaceFinding) bool { return f.Blocking })
}

func (a *ServerSurfaceAudit) HasWarnings() bool {
	return a != nil && len(a.Findings) > 0
}

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

func (a *ServerSurfaceAudit) auditEntry(serverDir string, entry os.DirEntry) {
	name := entry.Name()
	if len([]rune(name)) > surfaceMaxNameRunes || containsControlByte(name) || !surfacePrintable(name) || surfaceHasRTLOverride(name) {
		a.Findings = append(a.Findings, SurfaceFinding{
			Name: name, Reason: surfaceReasonBadName,
			Detail: "文件名包含控制字符或长度超过上限", Blocking: true,
		})
		return
	}
	info, err := os.Lstat(filepath.Join(serverDir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		a.Findings = append(a.Findings, SurfaceFinding{
			Name: name, Reason: surfaceReasonUnreadable,
			Detail: "无法读取条目属性", Blocking: false,
		})
		return
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		a.Findings = append(a.Findings, SurfaceFinding{
			Name: name, Reason: surfaceReasonSymlink,
			Detail: "根层存在符号链接，可能把启动读取引向目录外", Blocking: true,
		})
		return
	}
	if mode.IsDir() {
		return
	}
	if !mode.IsRegular() {
		a.Findings = append(a.Findings, SurfaceFinding{
			Name: name, Reason: surfaceReasonNotRegular,
			Detail: "根层存在设备/管道等特殊文件", Blocking: true,
		})
		return
	}
	lower := strings.ToLower(name)
	for _, ext := range surfaceExecutableExts {
		if strings.HasSuffix(lower, ext) {
			a.Findings = append(a.Findings, SurfaceFinding{
				Name: name, Reason: surfaceReasonExecutable,
				Detail: "服务器目录根层存在可执行脚本/程序，可能被误双击运行", Blocking: true,
			})
			return
		}
	}
	if strings.HasSuffix(lower, ".jar") && !strings.HasSuffix(lower, "-server.jar") {
		a.Findings = append(a.Findings, SurfaceFinding{
			Name: name, Reason: surfaceReasonExtraJar,
			Detail: "根层存在非服务端命名规则的 jar，可能被误当服务端启动", Blocking: false,
		})
	}
}

func surfaceHasRTLOverride(name string) bool {
	for _, r := range name {
		if r == '\u202e' || r == '\u202d' || r == '\u2066' || r == '\u2067' {
			return true
		}
	}
	return false
}

func surfacePrintable(name string) bool {
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
