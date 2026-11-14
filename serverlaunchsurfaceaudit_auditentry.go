package main

import (
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

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
