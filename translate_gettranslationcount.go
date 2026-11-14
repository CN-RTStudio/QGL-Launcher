package main

import (
	"strings"
)

func (a *App) GetTranslationCount() int {
	loadTranslations()
	translationMutex.RLock()
	defer translationMutex.RUnlock()
	return len(translationEntries)
}

// fuzzyMatch 模糊匹配：检查两个字符串的相似度
func fuzzyMatch(s, t string) float64 {
	s = strings.ToLower(s)
	t = strings.ToLower(t)
	if s == t {
		return 1.0
	}
	// 计算 Levenshtein 距离的简化版本
	lenS := len(s)
	lenT := len(t)
	if lenS == 0 { return 0 }
	if lenT == 0 { return 0 }

	matrix := make([][]int, lenS+1)
	for i := range matrix {
		matrix[i] = make([]int, lenT+1)
		matrix[i][0] = i
	}
	for j := 0; j <= lenT; j++ {
		matrix[0][j] = j
	}
	for i := 1; i <= lenS; i++ {
		for j := 1; j <= lenT; j++ {
			cost := 1
			if s[i-1] == t[j-1] {
				cost = 0
			}
			matrix[i][j] = min3(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}
	maxLen := lenS
	if lenT > maxLen { maxLen = lenT }
	return 1.0 - float64(matrix[lenS][lenT])/float64(maxLen)
}

func min3(a, b, c int) int {
	if a < b { if a < c { return a } else { return c } }
	if b < c { return b }
	return c
}

// isChinese 判断字符串是否包含中文
