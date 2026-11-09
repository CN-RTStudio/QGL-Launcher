package main

//
//

import (
	"os"
	"path/filepath"
	"strings"
)

// PreflightIssue 是一条预检发现。
type PreflightIssue struct {
	Kind  string `json:"kind"`  // critical / warning
	Code  string `json:"code"`  // 机器可读码，例如 java-path-unsafe
	Field string `json:"field"` // java / gamedir / natives / disk
	Text  string `json:"text"`  // 中文说明（进审计/日志）
}

// preflightCritical / preflightWarning 是 Kind 的取值。
const (
	preflightCritical = "critical"
	preflightWarning  = "warning"
)

// preflightMaxIssueTextLen 限制单条说明长度，防把超长路径写进审计。
const preflightMaxIssueTextLen = 256

// preflightMinFreeBytes 是启动预检的磁盘水位阈值（512 MiB）：低于此值游戏
// 很可能因磁盘满写盘失败，但下载流程仍会自行精确判断，这里只做提示。
const preflightMinFreeBytes = 512 << 20

// checkJavaBinary 校验 Java 可执行文件路径：
//   - 字符级安全（复用 sanitizePathComponent 的禁段/控制字符口径）；
//   - 必须存在、必须是常规文件（不是目录）；
//   - Windows 上拒绝 reparse point（符号链接/junction），防止配置项被换成
//     指向任意程序的链接入口。
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

// isWindowsReparsePoint 判断路径是否带重解析点属性（Windows 符号链接/junction）。
// 非 Windows 平台恒返回 false（编译期分平台：见 launchpreflight_windows.go）。
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

// checkDiskHeadroom 校验目标磁盘剩余空间是否足够。不足时给 warning（下载会
// 在下载前自行判断；这里只拦“明显不可能跑起来”的极端情况）。
