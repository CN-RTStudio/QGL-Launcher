package main

import "strings"

func capTranslateInput(s string) string {
	r := []rune(s)
	if len(r) > maxTranslateInputRunes {
		r = r[:maxTranslateInputRunes]
	}
	return string(r)
}
func (a *App) TranslateModName(english string) string {
	english = capTranslateInput(english)
	// 匹配用查询走有界内核：去控制字符、限长、去首尾空白；规范化后为空则不查表，
	// 直接原样返回（保持对空输入的历史行为）。
	clean, ok := normalizeTranslateQuery(english)
	if !ok {
		return english
	}
	loadTranslations()

	translationMutex.RLock()
	defer translationMutex.RUnlock()

	lowerEnglish := strings.ToLower(clean)

	// 精确匹配（O(1)）
	if chinese, ok := exactTranslations[lowerEnglish]; ok {
		return chinese
	}

	// 前缀匹配：已按长度降序排好，命中即返回
	for _, rule := range prefixTranslations {
		if strings.HasPrefix(lowerEnglish, rule.prefix) {
			return rule.chinese
		}
	}

	// 包含匹配：只跑精确条目（@ 条目已在 prefix 阶段处理过），
	// 而且 containsEntries 已按 key 长度降序排好。
	for _, entry := range containsEntries {
		key := entry.English
		if len(key) > 3 && strings.Contains(lowerEnglish, key) {
			return entry.Chinese
		}
	}

	return english
}
