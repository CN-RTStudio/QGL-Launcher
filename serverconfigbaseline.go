package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	baselineReasonCreated    = "created"
	baselineReasonModified   = "modified"
	baselineReasonRemoved    = "removed"
	baselineReasonAdded      = "added"
	baselineReasonCorrupt    = "corrupt"
	baselineReasonUnreadable = "unreadable"

	baselineVersion  = 1
	baselineMaxBytes = 4 << 20
)

var baselineFileNames = []string{
	"server.properties",
	"ops.json",
	"whitelist.json",
	"banned-players.json",
	"banned-ips.json",
	"eula.txt",
}

type BaselineFinding = auditFinding

type BaselineAudit struct {
	Path     string
	Created  bool
	Hashes   map[string]string
	Findings []BaselineFinding
}
type baselineStore struct {
	Version   int               `json:"version"`
	ServerDir string            `json:"serverDir"`
	Files     map[string]string `json:"files"`
}

func (a *BaselineAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f BaselineFinding) bool { return f.Blocking })
}
func (a *BaselineAudit) HasWarnings() bool {
	return a != nil && len(a.Findings) > 0
}
func (a *BaselineAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodes(a.Findings, func(f BaselineFinding) string { return f.Reason })
}

func (a *BaselineAudit) Describe() string {
	if a == nil {
		return ""
	}
	if len(a.Findings) == 0 {
		return "服务器配置文件与基线一致"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s): %s", f.File, f.Reason, f.Detail))
	}
	return strings.Join(parts, "; ")
}

func AuditServerConfigBaseline(serverDir, baselinePath string) (*BaselineAudit, error) {
	target := baselinePath
	if target == "" {
		defaultPath, err := defaultConfigBaselinePath(serverDir)
		if err != nil {
			return nil, err
		}
		target = defaultPath
	}
	audit := &BaselineAudit{Path: target, Hashes: map[string]string{}}
	hashes, err := hashBaselineFiles(serverDir, audit)
	if err != nil {
		return nil, err
	}
	audit.Hashes = hashes

	store, readErr := readBaselineStore(target)
	if readErr != nil {
		if !os.IsNotExist(readErr) {
			audit.Findings = append(audit.Findings, BaselineFinding{
				File: filepath.Base(target), Reason: baselineReasonCorrupt,
				Detail: "基线文件无法解析，已按当前状态重建", Blocking: false,
			})
			store = &baselineStore{Version: baselineVersion, ServerDir: serverDir, Files: map[string]string{}}
		} else {
			if err := writeBaselineStore(target, serverDir, hashes); err != nil {
				return nil, err
			}
			audit.Created = true
			return audit, nil
		}
	}
	compareBaseline(audit, store.Files, hashes)
	if err := writeBaselineStore(target, serverDir, hashes); err != nil {
		return nil, err
	}
	return audit, nil
}

func hashBaselineFiles(serverDir string, audit *BaselineAudit) (map[string]string, error) {
	hashes := make(map[string]string, len(baselineFileNames))
	for _, name := range baselineFileNames {
		path := filepath.Join(serverDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			audit.Findings = append(audit.Findings, BaselineFinding{
				File: name, Reason: baselineReasonUnreadable, Detail: "无法读取文件属性", Blocking: false,
			})
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > baselineMaxBytes {
			audit.Findings = append(audit.Findings, BaselineFinding{
				File: name, Reason: baselineReasonUnreadable,
				Detail: "文件是符号链接、特殊文件或超过体积上限，跳过基线比对", Blocking: false,
			})
			continue
		}
		sum, err := umfsFile(path)
		if err != nil {
			audit.Findings = append(audit.Findings, BaselineFinding{
				File: name, Reason: baselineReasonUnreadable, Detail: "计算摘要失败", Blocking: false,
			})
			continue
		}
		hashes[name] = sum
	}
	return hashes, nil
}
