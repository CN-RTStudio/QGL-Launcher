package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
