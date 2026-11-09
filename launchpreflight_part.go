package main

import "os"

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
