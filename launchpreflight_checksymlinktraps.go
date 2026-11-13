package main

import (
	"fmt"
)

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
