package main

import (
	"unicode"
)

func isChinese(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// GetModTranslationFileContent 获取翻译文件内容（用于显示开源协议信息）
