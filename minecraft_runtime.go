package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	maxNativeEntryBytes int64 = 256 << 20 // 256 MiB / 单个 native
	maxNativeTotalBytes int64 = 2 << 30   // 2 GiB / 单次解压总量
)

func (a *App) setGameLanguage(gameDir string, versionID string) {
	optionsPath := filepath.Join(gameDir, "options.txt")
	mcCodeMain := 0
	parts := strings.Split(versionID, "-")
	if len(parts) > 0 {
		verParts := strings.Split(parts[0], ".")
		if len(verParts) >= 2 {
			if v, err := strconv.Atoi(verParts[1]); err == nil {
				mcCodeMain = v
			}
		}
	}
	requiredLang := "zh_cn"
	if mcCodeMain > 0 && mcCodeMain < 12 {
		requiredLang = "zh_CN"
	}
	if _, err := os.Stat(optionsPath); os.IsNotExist(err) {
		yosbrPath := filepath.Join(gameDir, "config", "yosbr", "options.txt")
		if _, err2 := os.Stat(yosbrPath); err2 == nil {
			optionsPath = yosbrPath
			a.writeLog("检测到 Yosbr Mod，修改其 options.txt")
		}
	}
	data, err := readBoundedFile(optionsPath, localTextConfigMaxBytes)
	if err != nil {
		if errors.Is(err, errLocalFileTooLarge) {
			// 异常巨大的 options.txt：绝不能走下面“创建默认文件”的分支把它截断覆盖，
			// 直接跳过本次语言设置，保留用户原文件。
			a.writeLog("options.txt 异常过大，跳过语言设置以免破坏文件: %v", err)
			recordSecurityEvent("local-config", auditSeverityWarn, auditActionBlocked,
				"minecraft", "options.txt 超过有界读取上限，已跳过语言改写")
			return
		}
		content := fmt.Sprintf("lang:%s\n", requiredLang)
		if err := secureWritePrivateFile(optionsPath, []byte(content)); err != nil {
			a.writeLog("创建 options.txt 失败: %v", err)
		} else {
			a.writeLog("已创建 options.txt，设置语言为 %s", requiredLang)
		}
		return
	}
	lines := strings.Split(string(data), "\n")
	found, hasSaves := false, false
	if info, err := os.Stat(filepath.Join(gameDir, "saves")); err == nil && info.IsDir() {
		hasSaves = true
	}
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "lang:") {
			currentLang := strings.TrimSpace(strings.TrimPrefix(line, "lang:"))
			if currentLang == requiredLang {
				a.writeLog("游戏语言已为 %s，无需修改", requiredLang)
				return
			}
			if hasSaves && currentLang != "" && currentLang != "none" {
				a.writeLog("检测到已有存档，保留用户语言设置: %s", currentLang)
				return
			}
			lines[i] = fmt.Sprintf("lang:%s", requiredLang)
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf("lang:%s", requiredLang))
	}
	newData := strings.Join(lines, "\n")
	if err := secureWritePrivateFile(optionsPath, []byte(newData)); err != nil {
		a.writeLog("写入 options.txt 失败: %v", err)
	} else {
		a.writeLog("已将游戏语言设置为 %s", requiredLang)
	}
}

func (a *App) ensureNativesForLoader(mcDir string, versionID string, versionDir string, nativesDir string, versionJSON *VersionJSON) {
	if rawParent := strings.TrimSpace(versionJSON.InheritsFrom); rawParent != "" {
		parentName := safeVersionName(rawParent)
		if parentName != "" {
			parentNativesDir := filepath.Join(mcDir, "versions", parentName, parentName+"-natives")
			if entries, err := os.ReadDir(parentNativesDir); err == nil && len(entries) > 0 {
				fmt.Printf("从父版本复制 natives: %s -> %s\n", parentNativesDir, nativesDir)
				copyDirContents(parentNativesDir, nativesDir)
				return
			}
		}
	}
	versionsDir := filepath.Join(mcDir, "versions")
	entries, _ := os.ReadDir(versionsDir)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidateNatives := filepath.Join(versionsDir, entry.Name(), entry.Name()+"-natives")
		if info, err := os.Stat(candidateNatives); err == nil && info.IsDir() {
			if subEntries, err2 := os.ReadDir(candidateNatives); err2 == nil && len(subEntries) > 0 {
				fmt.Printf("从 %s 复制 natives 到 %s\n", candidateNatives, nativesDir)
				copyDirContents(candidateNatives, nativesDir)
				return
			}
		}
	}
	fmt.Printf("尝试重新解压 natives 到: %s\n", nativesDir)
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
}

// copyDirContents 只复制 srcDir 顶层的普通文件到 dstDir（不递归）。
// 显式跳过符号链接 / 特殊文件，并对单文件与总量设上限：源目录是各版本 natives，
// 正常只含体积有限的 .dll/.so；跳过链接可避免把链接目标（可能指向目录外敏感文件）
// 以普通文件形式带进运行目录。
//
// 复制统一走 copyFileSecure 的“流式 + 原子写 + 源/目标符号链接拒绝 + 多读 1
// 判超限”，不再用 os.ReadFile 把单个最多 256MiB 的文件整体读进内存（那会造成
// 与文件等大的瞬时内存峰值）；这里只按声明大小记账，实际超限由 copyFileSecure
// 在流式阶段兜底。

// generateOfflineUUID 使用 UMFS 哈希（bool-hybrid-array 生态）
