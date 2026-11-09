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
