package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func pcReadBounded(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	limited := io.LimitReader(f, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("超过体积上限 %d", maxBytes)
	}
	return data, nil
}

func pcInspectFile(audit *PluginConfigAudit, rel, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		audit.add(rel, pcReasonUnreadable, "无法读取插件配置", true)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(rel, pcReasonSymlink, "插件配置是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(rel, pcReasonUnreadable, "插件配置不是普通文件", true)
		return
	}
	if info.Size() > pcMaxFileBytes {
		audit.add(rel, pcReasonTooLarge, "插件配置超过体积预算", true)
		return
	}
	if info.Mode().Perm()&0o022 != 0 {
		audit.add(rel, pcReasonWorldReadable, "插件配置对其他用户可写", false)
	}
	data, err := pcReadBounded(path, pcMaxFileBytes)
	if err != nil {
		audit.add(rel, pcReasonUnreadable, "插件配置读取失败", false)
		return
	}
	pcScanLines(audit, rel, data)
}

func AuditServerPluginConfig(serverDir string) PluginConfigAudit {
	audit := PluginConfigAudit{Dir: serverDir}
	root := filepath.Join(serverDir, "plugins")
	entries, err := os.ReadDir(root)
	if err != nil {
		audit.add("plugins", pcReasonMissing, "未发现 plugins 目录", false)
		audit.add("", pcReasonOK, "无插件配置", false)
		return audit
	}
	for _, plugin := range entries {
		if len(audit.Files) >= pcMaxFiles {
			audit.add("plugins", pcReasonTooMany, "插件目录数量超过预算", true)
			break
		}
		base := filepath.Join(root, plugin.Name())
		if plugin.IsDir() {
			names, err := os.ReadDir(base)
			if err != nil {
				audit.add(filepath.Join("plugins", plugin.Name()), pcReasonUnreadable, "插件目录不可读", true)
				continue
			}
			for _, name := range names {
				if name.IsDir() {
					audit.add(filepath.Join("plugins", plugin.Name(), name.Name()), pcReasonDepthExceeded, "插件配置目录层级超出预算", false)
					continue
				}
				lower := strings.ToLower(name.Name())
				match := false
				for _, ext := range pcConfigExts {
					if strings.HasSuffix(lower, ext) {
						match = true
						break
					}
				}
				if !match {
					continue
				}
				rel := filepath.Join("plugins", plugin.Name(), name.Name())
				audit.Files = append(audit.Files, rel)
				pcInspectFile(&audit, rel, filepath.Join(base, name.Name()))
			}
			continue
		}
		lower := strings.ToLower(plugin.Name())
		for _, ext := range pcConfigExts {
			if !strings.HasSuffix(lower, ext) {
				continue
			}
			rel := filepath.Join("plugins", plugin.Name())
			audit.Files = append(audit.Files, rel)
			pcInspectFile(&audit, rel, base)
			break
		}
	}
	if len(audit.Findings) == 0 {
		audit.add("", pcReasonOK, "插件配置未发现风险", false)
	}
	return audit
}

type PluginConfigFinding = auditFinding

type PluginConfigAudit struct {
	Dir      string
	Files    []string
	Findings []PluginConfigFinding
}

func (a PluginConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginConfigFinding) bool { return f.Blocking })
}

func (a PluginConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginConfigFinding) bool { return !f.Blocking && f.Reason != pcReasonOK })
}

func (a PluginConfigAudit) Codes() []string {
	return findingCodesSkip(a.Findings, pcReasonOK, func(f PluginConfigFinding) string { return f.Reason })
}

func (a PluginConfigAudit) Describe() string {
	return describeLabeledFindings("未发现插件配置", a.Findings, 4, "",
		func(f PluginConfigFinding) string { return f.File },
		func(f PluginConfigFinding) string { return f.Reason })
}

func (a PluginConfigAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f PluginConfigFinding) bool { return f.Blocking }, func(f PluginConfigFinding) bool { return !f.Blocking && f.Reason != pcReasonOK })
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}

func (a *PluginConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pcMaxFindings, PluginConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

const (
	mpeMaxFindings      = 48
	mpeMaxJarBytes      = 512 * 1024 * 1024
	mpeMaxEntryBytes    = 256 * 1024 * 1024
	mpeMaxEntries       = 20000
	mpeMaxRatio         = 1000
	mpeRatioMinBytes    = 1024 * 1024
	mpeMaxNestedJars    = 8
	mpeMaxPlugins       = 256
	mpeReasonOK         = "ok"
	mpeReasonMissing    = "missing"
	mpeReasonSymlink    = "symlink"
	mpeReasonTooLarge   = "too-large"
	mpeReasonBadJar     = "bad-jar"
	mpeReasonTraversal  = "entry-traversal"
	mpeReasonDuplicate  = "duplicate-entry"
	mpeReasonEntryLarge = "entry-too-large"
	mpeReasonBomb       = "zip-bomb"
	mpeReasonEntryCount = "entry-overflow"
	mpeReasonNested     = "nested-jars"
	mpeReasonBadName    = "bad-jar-name"
)
