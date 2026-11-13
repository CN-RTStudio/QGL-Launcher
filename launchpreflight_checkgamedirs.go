package main

import (
	"os"
)

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
