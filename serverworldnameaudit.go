package main

import (
	"path/filepath"
	"strings"
)

const (
	swnMaxFindings     = 32
	swnMaxProps        = 256 * 1024
	swnReasonMissing   = "missing"
	swnReasonSymlink   = "symlink"
	swnReasonTooLarge  = "too-large"
	swnReasonUnread    = "unreadable"
	swnReasonName      = "level-name-invalid"
	swnReasonDirLink   = "world-dir-symlink"
	swnReasonLevelType = "level-type-unknown"
	swnReasonGenerator = "generator-settings-present"
	swnReasonNoProps   = "properties-missing"
)

var swnKnownLevelTypes = map[string]bool{
	"default":              true,
	"flat":                 true,
	"large_biomes":         true,
	"amplified":            true,
	"single_biome_surface": true,
	"normal":               true,
	"customized":           true,
}

type WorldNameFinding = auditFinding

type WorldNameAudit struct {
	ServerDir string
	Findings  []WorldNameFinding
}

func (a *WorldNameAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, swnMaxFindings, WorldNameFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WorldNameAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WorldNameFinding) bool { return f.Blocking })
}

func (a *WorldNameAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WorldNameAudit) Describe() string {
	return describeFileReasonDetail("世界目录配置未发现风险", a.Findings, 12)
}

func swnValidateLevelName(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "level-name 为空"
	}
	if filepath.IsAbs(trimmed) || strings.HasPrefix(trimmed, "/") {
		return "level-name 使用绝对路径"
	}
	if strings.Contains(trimmed, "..") {
		return "level-name 包含越界片段"
	}
	if strings.ContainsAny(trimmed, "\\:") {
		return "level-name 包含反斜杠或盘符"
	}
	if cfgHasControlChars(trimmed) {
		return "level-name 含控制字符"
	}
	return ""
}
