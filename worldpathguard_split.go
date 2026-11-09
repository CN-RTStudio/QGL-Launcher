package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func AuditWorldPath(serverDir, levelName string) (WorldPathAudit, error) {
	audit := WorldPathAudit{LevelName: levelName, Reason: worldReasonOK}
	if !safeWorldLevelName(levelName) {
		audit.Reason = worldReasonUnsafeName
		return audit, nil
	}
	root, err := canonicalAbs(serverDir)
	if err != nil {
		return audit, fmt.Errorf("解析服务器目录失败: %v", err)
	}
	target := filepath.Join(root, levelName)
	audit.Path = target
	if !PathWithinRoot(target, root) {
		audit.Reason = worldReasonEscape
		return audit, nil
	}
	info, err := os.Lstat(target)
	if err != nil {
		if os.IsNotExist(err) {
			audit.Warnings = append(audit.Warnings, "世界目录尚不存在，首次启动后由服务端创建")
			return audit, nil
		}
		return audit, fmt.Errorf("检查世界目录失败: %v", err)
	}
	audit.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Symlink = true
		audit.Reason = worldReasonSymlink
		return audit, nil
	}
	if !info.IsDir() {
		audit.Reason = worldReasonNotDirectory
		return audit, nil
	}
	return audit, nil
}

func readWorldLevelName(serverDir string) (string, bool, error) {
	path := filepath.Join(serverDir, "server.properties")
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("检查 server.properties 失败: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", false, fmt.Errorf("server.properties 不是普通文件，拒绝读取")
	}
	if info.Size() > worldProbeBytes {
		return "", false, fmt.Errorf("server.properties 超过 %d 字节上限", worldProbeBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", false, fmt.Errorf("打开 server.properties 失败: %v", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, worldProbeBytes+1))
	if err != nil {
		return "", false, fmt.Errorf("读取 server.properties 失败: %v", err)
	}
	props := parseServerProperties(raw)
	value, ok := props.Get("level-name")
	if !ok {
		return "", false, nil
	}
	return strings.TrimSpace(value), true, nil
}

func describeWorldPathAudit(audit WorldPathAudit) string {
	var parts []string
	parts = append(parts, audit.Describe())
	if audit.Path != "" {
		parts = append(parts, "路径 "+audit.Path)
	}
	if audit.Present && !audit.Symlink {
		parts = append(parts, "目录已存在")
	}
	if len(audit.Warnings) > 0 {
		parts = append(parts, strings.Join(audit.Warnings, "；"))
	}
	return strings.Join(parts, "，")
}
