package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

)

func isDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true, err
	}
	return len(entries) == 0, nil
}

// setGameLanguage 设置游戏语言为中文（参考 PCL 的 options.txt 修改逻辑）
// 修改游戏目录下的 options.txt 中的 lang 字段
// MC 版本语言格式：
//   1.1~1.5: zh_CN（最后两位必须大写，否则崩溃）
//   1.6~1.10: zh_CN（zh_cn 会自动切换为英文）
//   1.11~1.12: zh_cn（zh_CN 虽然显示中文但语言设置会错误显示英文）
//   1.13+: zh_cn（zh_CN 会自动切换为英文）
func (a *App) setGameLanguage(gameDir string, versionID string) {
	optionsPath := filepath.Join(gameDir, "options.txt")

	// 提取 MC 主版本号
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

	// 确定语言代码
	requiredLang := "zh_cn"
	if mcCodeMain > 0 && mcCodeMain < 12 {
		// 1.1~1.11 需要大写后缀
		requiredLang = "zh_CN"
	}

	// 检查 Yosbr Mod 兼容
	if _, err := os.Stat(optionsPath); os.IsNotExist(err) {
		yosbrPath := filepath.Join(gameDir, "config", "yosbr", "options.txt")
		if _, err2 := os.Stat(yosbrPath); err2 == nil {
			optionsPath = yosbrPath
			a.writeLog("检测到 Yosbr Mod，修改其 options.txt")
		}
	}

	// 读取 options.txt
	data, err := os.ReadFile(optionsPath)
	if err != nil {
		// 文件不存在，创建新的
		content := fmt.Sprintf("lang:%s\n", requiredLang)
		if err := os.WriteFile(optionsPath, []byte(content), 0644); err != nil {
			a.writeLog("创建 options.txt 失败: %v", err)
		} else {
			a.writeLog("已创建 options.txt，设置语言为 %s", requiredLang)
		}
		return
	}

	// 解析并修改 lang 字段
	lines := strings.Split(string(data), "\n")
	found := false
	hasSaves := false
	// 检查是否有存档目录（有存档说明不是首次启动，不强制修改语言）
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
			// 如果有存档，不强制修改用户已有的语言设置
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
		// 没有找到 lang 行，添加
		lines = append(lines, fmt.Sprintf("lang:%s", requiredLang))
	}

	// 写回文件
	newData := strings.Join(lines, "\n")
	if err := os.WriteFile(optionsPath, []byte(newData), 0644); err != nil {
		a.writeLog("写入 options.txt 失败: %v", err)
	} else {
		a.writeLog("已将游戏语言设置为 %s", requiredLang)
	}
}

// ensureNativesForLoader 为加载器版本确保 natives 存在
// 原版下载时 natives 解压到了 versions/{mcVersion}/{mcVersion}-natives，
// 但加载器版本（Forge/Fabric/NeoForge）启动时需要 versions/{loaderVersion}/{loaderVersion}-natives
