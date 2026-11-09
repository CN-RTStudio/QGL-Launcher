package main

import "strings"

func (a *App) SearchModsByChineseName(chineseQuery string) []string {
	chineseQuery = capTranslateInput(chineseQuery)
	// 查询走有界内核：剔除控制字符 / 限长 / 去空白；为空直接返回 nil，不扫全表。
	query, ok := normalizeTranslateQuery(chineseQuery)
	if !ok {
		return nil
	}
	loadTranslations()

	translationMutex.RLock()
	defer translationMutex.RUnlock()

	query = strings.ToLower(query)
	seen := make(map[string]struct{})
	var results []string

	for _, entry := range translationEntries {
		chineseLower := strings.ToLower(entry.Chinese)
		if strings.Contains(chineseLower, query) {
			// 去重 + 硬上限，达到上限立即停止全表扫描（极短词命中全表时止损）。
			var full bool
			results, full = appendDistinctOrdered(results, seen, entry.English, maxChineseSearchResults)
			if full {
				break
			}
		}
	}

	return results
}

func (a *App) GetTranslationCount() int {
	loadTranslations()
	translationMutex.RLock()
	defer translationMutex.RUnlock()
	return len(translationEntries)
}

func (a *App) GetModTranslationFileContent() (string, error) {
	data, err := modDataFile.ReadFile("resources/ModData.txt")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (a *App) ReadLicenseFile() string {
	data, err := modDataFile.ReadFile("resources/APACHE_LICENSE.txt")
	if err != nil {
		return ""
	}
	return string(data)
}
