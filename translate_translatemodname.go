package main

import (
	"strings"
)

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
