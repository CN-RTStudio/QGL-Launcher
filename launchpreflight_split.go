package main

//
//

import (
	"fmt"
)

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
