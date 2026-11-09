package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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

func compareBaseline(audit *BaselineAudit, previous, current map[string]string) {
	for name, oldSum := range previous {
		currentSum, ok := current[name]
		if !ok {
			audit.Findings = append(audit.Findings, BaselineFinding{
				File: name, Reason: baselineReasonRemoved,
				Detail: "上次记录存在的配置文件已消失", Blocking: false,
			})
			continue
		}
		if oldSum != currentSum {
			audit.Findings = append(audit.Findings, BaselineFinding{
				File: name, Reason: baselineReasonModified,
				Detail: fmt.Sprintf("摘要由 %s 变为 %s", shortSum(oldSum), shortSum(currentSum)), Blocking: false,
			})
		}
	}
	for name := range current {
		if _, ok := previous[name]; ok {
			continue
		}
		audit.Findings = append(audit.Findings, BaselineFinding{
			File: name, Reason: baselineReasonAdded,
			Detail: "基线中没有该配置文件，已纳入本次基线", Blocking: false,
		})
	}
}

func readBaselineStore(path string) (*baselineStore, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > baselineMaxBytes {
		return nil, fmt.Errorf("基线文件不是可信普通文件")
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return nil, err
	}
	var store baselineStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	if store.Version != baselineVersion || store.Files == nil {
		return nil, fmt.Errorf("基线版本不支持")
	}
	return &store, nil
}

func writeBaselineStore(path, serverDir string, hashes map[string]string) error {
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	store := baselineStore{Version: baselineVersion, ServerDir: serverDir, Files: hashes}
	return writePrivateJSONBounded(path, store, baselineMaxBytes)
}

func defaultConfigBaselinePath(serverDir string) (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("无法定位配置目录: %w", err)
	}
	canonical, err := canonicalAbs(serverDir)
	if err != nil {
		return "", fmt.Errorf("服务器目录无法归一: %w", err)
	}
	digest := NewUMFSHash()
	digest.Write([]byte(strings.ToLower(canonical)))
	name := hex.EncodeToString(digest.Sum(nil))
	return filepath.Join(root, "QingLongLauncher", "config-baseline", name+".json"), nil
}

func shortSum(sum string) string {
	if len(sum) <= 12 {
		return sum
	}
	return sum[:12]
}
