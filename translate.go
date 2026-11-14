package main

import (
	"bufio"
	"embed"
	"strings"
	"sync"
)

//go:embed resources/ModData.txt
var modDataFile embed.FS

// ModTranslationEntry 翻译条目
type ModTranslationEntry struct {
	English string `json:"english"`
	Chinese string `json:"chinese"`
}

// modTranslationCache 翻译缓存
var (
	translationEntries []ModTranslationEntry
	translationLoaded  bool
	translationMutex  sync.RWMutex
)

// loadTranslations 加载翻译对照表（只加载一次）
func loadTranslations() {
	translationMutex.Lock()
	defer translationMutex.Unlock()

	if translationLoaded {
		return
	}
	translationLoaded = true

	data, err := modDataFile.ReadFile("resources/ModData.txt")
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 每行用 ¨ 分隔多个映射条目
		parts := strings.Split(line, "¨")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			// 每个 | 分隔 英文标识|中文翻译
			idx := strings.Index(part, "|")
			if idx <= 0 || idx >= len(part)-1 {
				continue
			}
			english := strings.TrimSpace(part[:idx])
			chinese := strings.TrimSpace(part[idx+1:])
			if english != "" && chinese != "" {
				translationEntries = append(translationEntries, ModTranslationEntry{
					English: english,
					Chinese: chinese,
				})
			}
		}
	}
}

// TranslateModName 将英文 Mod 名称/Slug 翻译为中文
// 支持精确匹配和前缀匹配
