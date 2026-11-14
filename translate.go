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
func (a *App) TranslateModName(english string) string {
	loadTranslations()

	translationMutex.RLock()
	defer translationMutex.RUnlock()

	lowerEnglish := strings.ToLower(strings.TrimSpace(english))

	// 1. 精确匹配（去掉 @ 后缀比较）
	for _, entry := range translationEntries {
		key := strings.TrimSuffix(entry.English, "@")
		if strings.ToLower(key) == lowerEnglish {
			return entry.Chinese
		}
	}

	// 2. 前缀匹配（@ 开头的条目，如 "industrial-craft@" 匹配 "industrial-craft-2-2-8-110"）
	for _, entry := range translationEntries {
		if strings.HasSuffix(entry.English, "@") {
			prefix := strings.ToLower(entry.English[:len(entry.English)-1])
			if strings.HasPrefix(lowerEnglish, prefix) {
				return entry.Chinese
			}
		}
	}

	// 3. 包含匹配（不带 @ 的条目，检查英文是否包含 key）
	for _, entry := range translationEntries {
		if !strings.HasSuffix(entry.English, "@") {
			key := strings.ToLower(entry.English)
			if strings.Contains(lowerEnglish, key) && len(key) > 3 {
				return entry.Chinese
			}
		}
	}

	return english // 无匹配则返回原名
}

// SearchModsByChineseName 通过中文名称搜索 Mod（返回所有匹配的英文原名）
func (a *App) SearchModsByChineseName(chineseQuery string) []string {
	loadTranslations()

	translationMutex.RLock()
	defer translationMutex.RUnlock()

	query := strings.ToLower(strings.TrimSpace(chineseQuery))
	var results []string

	for _, entry := range translationEntries {
		chineseLower := strings.ToLower(entry.Chinese)
		if strings.Contains(chineseLower, query) {
			results = append(results, entry.English)
		}
	}

	return results
}

// GetTranslationCount 获取已加载的翻译条目数量
