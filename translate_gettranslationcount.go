package main

import (
)

func (a *App) GetTranslationCount() int {
	loadTranslations()
	translationMutex.RLock()
	defer translationMutex.RUnlock()
	return len(translationEntries)
}

// fuzzyMatch 模糊匹配：检查两个字符串的相似度
