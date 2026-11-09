package main

import (
	"fmt"
	"strings"
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
