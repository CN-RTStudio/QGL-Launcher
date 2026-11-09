package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) shouldIncludeLib(lib Library) bool {
	// 库规则统一走 ruleengine：按 Mojang 语义评估 os.name/arch/version 与 features，
	// 不再只判 os.name=="windows"（旧逻辑会误选 osx/linux 专属库、忽略架构与版本）。
	return libraryRulesAllow(lib.Rules, currentRuleEnv())
}
func libGroupArtifact(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) >= 2 {
		return parts[0] + ":" + parts[1]
	}
	return name
}
func isValidMavenToken(token string) bool {
	if token == "" || token == "." || token == ".." {
		return false
	}
	if len(token) > 255 {
		return false
	}
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			// 字母数字
		case strings.ContainsRune("-_.@+", r):
			// Maven 常见合法字符
		default:
			return false
		}
	}
	return true
}
func mavenNameToPath(name string, libsDir string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}
	// 坐标的每一段都必须是干净的 Maven token；groupId 的每个 "." 分段也要
	// 单独校验，否则 "..\.." 之类会在 ReplaceAll 之后变成路径穿越。
	groupParts := strings.Split(parts[0], ".")
	for _, seg := range groupParts {
		if !isValidMavenToken(seg) {
			return ""
		}
	}
	artifact, version := parts[1], parts[2]
	if !isValidMavenToken(artifact) || !isValidMavenToken(version) {
		return ""
	}
	classifier := ""
	if len(parts) >= 4 {
		if !isValidMavenToken(parts[3]) {
			return ""
		}
		classifier = "-" + parts[3]
	}
	group := strings.Join(groupParts, string(os.PathSeparator))
	fileName := fmt.Sprintf("%s-%s%s.jar", artifact, version, classifier)
	rel := filepath.Join(group, artifact, version, fileName)
	// 拼好后再用统一的相对路径校验兜底，确保结果一定在 libraries 内。
	if isSafeRelPath(rel) == "" {
		return ""
	}
	return filepath.Join(libsDir, rel)
}
