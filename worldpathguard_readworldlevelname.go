package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

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
