package main

import (
	"path/filepath"
	"strings"
)

// isUNC 报告路径是否为 Windows UNC 网络路径（\\host\share）。
func isUNC(p string) bool {
	return strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//")
}

// containedInAnyRoot 报告归一化后的目标是否落在任一允许根内（根自身也算）。
func containedInAnyRoot(target string, roots []string) bool {
	if len(roots) == 0 {
		return false
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	for _, root := range roots {
		if _, ok := PathWithin(root, absTarget); ok {
			return true
		}
	}
	return false
}

// auditJavaExe 校验 java 可执行路径：要求绝对、长度有界、非 UNC、无穿越、无控制符，
// Windows 上必须是 .exe（防止被指到脚本 / 批处理）。
