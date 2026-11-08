package main

// launchpreflight.go —— 启动预检（launch preflight）纯函数内核。
//
// 背景：
//    LaunchGame 在 cmd.Start() 前做了 mods 扫描、命令行审计、环境剥离等，但
//    有两个“执行目标”层面的缺口：
//      1) Java 可执行文件路径来自用户配置（SelectJavaForVersion），没有校验
//         “它真的是一个可执行文件”。若该路径被替换成任意可执行文件（比如被
//         拖进来的木马），游戏启动 = 直接执行该文件；
//      2) 没有统一的“目录就绪”检查：natives 目录为空、游戏目录缺失、磁盘
//         剩余空间不足时，游戏仍会被拉起（然后以神秘方式失败）。
//    本模块把这些检查做成纯函数集合 + 一次聚合预检，结果可单测、可读。
//
// 设计：
//    - 纯函数：给定输入（Java 路径 / 目录 / 磁盘余量），返回结构化问题列表，
//      不触碰文件系统以外的状态，便于单测；
//    - Java 路径校验复用 sanitizePathComponent 口径做字符级检查，并做
//      “常规文件、非目录”的实体检查；Windows 上拒绝 reparse point（符号链接 /
//      junction）指向的 java.exe，防止配置项被换成链接到任意程序的入口；
//    - 磁盘余量阈值来自 diskplan 的既有口径（对齐不新造）；
//    - 聚合预检（PreflightLaunches）在 LaunchGame 中调用：任一 critical 问题
//      直接拒绝启动，warning 只记录审计。

import (
	"fmt"
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
