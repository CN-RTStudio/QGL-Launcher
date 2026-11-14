package main

import (
	"os"
	"path/filepath"
)

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
