package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
)

func (a *App) GetLaunchCommand(versionID string) (string, error) {
	if err := sanitizePathComponent(versionID); err != nil {
		return "", fmt.Errorf("无效的版本ID: %v", err)
	}
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)
	versionJSON, err := a.resolveVersionJSON(versionID)
	if err != nil {
		return "", fmt.Errorf("解析版本 JSON 失败: %v", err)
	}
	a.fixMissingLibraries(mcDir, versionJSON)
	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	// natives 目录由 extractNativesFromJSON 内部统一以 0700 创建/收权。
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
	if empty, _ := isDirEmpty(nativesDir); empty {
		a.ensureNativesForLoader(mcDir, versionID, versionDir, nativesDir, versionJSON)
	}
	allArgs, _, _, _ := a.buildLaunchArgs(versionID, versionJSON, mcDir, versionDir)
	javaEntry, _ := a.SelectJavaForVersion(versionID)
	javaPath := javaEntry.Path

	cmdParts := []string{syscall.EscapeArg(javaPath)}
	for _, arg := range allArgs {
		cmdParts = append(cmdParts, syscall.EscapeArg(arg))
	}
	return strings.Join(cmdParts, " "), nil
}

// dumpCrashContext 在判定崩溃后读取“本局”（startTime 之后）新生成的
// crash-reports / hs_err 崩溃产物摘要，追加到崩溃原因；找不到或读取失败都静默
// 退化为原原因，绝不阻塞崩溃上报。gameDir 即游戏进程的工作目录（cmd.Dir）。
