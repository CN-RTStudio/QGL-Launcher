package main

import (
	"os"
	"path/filepath"
	"strings"
)

type PreflightIssue struct {
	Kind  string `json:"kind"`  // critical / warning
	Code  string `json:"code"`  // 机器可读码，例如 java-path-unsafe
	Field string `json:"field"` // java / gamedir / natives / disk
	Text  string `json:"text"`  // 中文说明（进审计/日志）
}

const (
	preflightCritical = "critical"
	preflightWarning  = "warning"
)
const preflightMaxIssueTextLen = 256
const preflightMinFreeBytes = 512 << 20

func checkJavaBinary(javaPath string) []PreflightIssue {
	var issues []PreflightIssue
	base := filepath.Base(javaPath)
	if base == "" || base == "." || base == ".." {
		issues = append(issues, PreflightIssue{Kind: preflightCritical, Code: "java-path-unsafe",
			Field: "java", Text: "Java 可执行文件名非法"})
		return issues
	}
	if strings.ContainsAny(javaPath, "\x00\r\n") {
		issues = append(issues, PreflightIssue{Kind: preflightCritical, Code: "java-path-unsafe",
			Field: "java", Text: "Java 路径含控制字符"})
		return issues
	}
	info, err := os.Stat(javaPath)
	if err != nil {
		issues = append(issues, PreflightIssue{Kind: preflightCritical, Code: "java-path-missing",
			Field: "java", Text: "Java 可执行文件不存在: " + truncatePreflightText(err.Error())})
		return issues
	}
	if info.IsDir() {
		issues = append(issues, PreflightIssue{Kind: preflightCritical, Code: "java-path-is-dir",
			Field: "java", Text: "Java 路径指向目录而非可执行文件"})
		return issues
	}
	if info.Mode()&os.ModeSymlink != 0 {
		issues = append(issues, PreflightIssue{Kind: preflightCritical, Code: "java-path-symlink",
			Field: "java", Text: "Java 路径是符号链接，拒绝执行（防链接到任意程序）"})
		return issues
	}
	if isWindowsReparsePoint(javaPath) {
		issues = append(issues, PreflightIssue{Kind: preflightCritical, Code: "java-path-reparse",
			Field: "java", Text: "Java 路径是重解析点（junction/symlink），拒绝执行"})
		return issues
	}
	return issues
}

func isWindowsReparsePoint(path string) bool {
	return hasWindowsReparseAttribute(path)
}

// checkGameDirs 校验游戏目录与 natives 目录：
//   - 游戏目录必须存在且是目录；
//   - natives 目录必须存在；为空时给 warning（某些版本用 JVM 内建解压，允许
//     为空，但提示以便排查“启动即崩”）。
