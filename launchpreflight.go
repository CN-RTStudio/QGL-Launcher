package main

import (
	"fmt"
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
func checkGameDirs(gameDir, nativesDir string) []PreflightIssue {
	var issues []PreflightIssue
	if gameDir != "" {
		info, err := os.Stat(gameDir)
		if err != nil || !info.IsDir() {
			issues = append(issues, PreflightIssue{Kind: preflightCritical, Code: "gamedir-missing",
				Field: "gamedir", Text: "游戏目录不存在或不可读: " + truncatePreflightText(gameDir)})
		}
	}
	if nativesDir != "" {
		info, err := os.Stat(nativesDir)
		if err != nil || !info.IsDir() {
			issues = append(issues, PreflightIssue{Kind: preflightCritical, Code: "natives-missing",
				Field: "natives", Text: "natives 目录不存在: " + truncatePreflightText(nativesDir)})
			return issues
		}
		empty, _ := isDirEmpty(nativesDir)
		if empty {
			issues = append(issues, PreflightIssue{Kind: preflightWarning, Code: "natives-empty",
				Field: "natives", Text: "natives 目录为空，可能由 JVM 内建解压补全"})
		}
	}
	return issues
}

func checkDiskHeadroom(gameDir string, minFreeBytes int64) []PreflightIssue {
	if gameDir == "" || minFreeBytes <= 0 {
		return nil
	}
	freeBytes, err := availableDiskBytes(gameDir)
	if err != nil {
		return []PreflightIssue{{Kind: preflightWarning, Code: "disk-uncheckable",
			Field: "disk", Text: "磁盘剩余空间检测失败: " + truncatePreflightText(err.Error())}}
	}
	if freeBytes < minFreeBytes {
		return []PreflightIssue{{Kind: preflightWarning, Code: "disk-low",
			Field: "disk", Text: "磁盘剩余空间不足（当前 <" + FormatBytes(freeBytes) + "）"}}
	}
	return nil
}

// checkSymlinkTraps 扫描游戏目录树中的符号链接 / junction 陷阱。
// 命中即 critical：链接会把后续写入（解压 natives、写 mod 缓存）重定向到
// 目录外任意路径。扫描超限（目录树失控）时降级为 warning 并给出提示。
func checkSymlinkTraps(gameDir string) []PreflightIssue {
	if gameDir == "" {
		return nil
	}
	traps, err := scanSymlinkTraps(gameDir)
	if err != nil {
		if len(traps) == 0 {
			return []PreflightIssue{{Kind: preflightWarning, Code: "symlink-scan-limited",
				Field: "gamedir", Text: "符号链接扫描因目录树过大提前停止: " + truncatePreflightText(err.Error())}}
		}
	}
	if len(traps) == 0 {
		return nil
	}
	summary := symlinkTrapSummary(traps, 8)
	first := ""
	if len(summary) > 0 {
		first = "，首例: " + summary[0]
	}
	return []PreflightIssue{{Kind: preflightCritical, Code: "symlink-trap",
		Field: "gamedir",
		Text:  fmt.Sprintf("游戏目录发现 %d 个符号链接陷阱%s", len(traps), first)}}
}

// truncatePreflightText 限制说明文本长度。
func truncatePreflightText(s string) string {
	if len(s) <= preflightMaxIssueTextLen {
		return s
	}
	return s[:preflightMaxIssueTextLen] + "…"
}

// aggregatePreflight 把全部检查聚合为一次预检。critical 存在时 isBlocked=true。
func aggregatePreflight(checks ...[]PreflightIssue) (issues []PreflightIssue, isBlocked bool) {
	for _, group := range checks {
		issues = append(issues, group...)
		if !isBlocked {
			for _, it := range group {
				if it.Kind == preflightCritical {
					isBlocked = true
					break
				}
			}
		}
	}
	return issues, isBlocked
}
