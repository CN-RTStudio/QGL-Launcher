package main

import (
	"os"
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
func (a *App) GetModTranslationFileContent() (string, error) {
	data, err := modDataFile.ReadFile("resources/ModData.txt")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ReadLicenseFile 读取 Apache License 文件内容
func (a *App) ReadLicenseFile() string {
	data, err := os.ReadFile("resources/APACHE_LICENSE.txt")
	if err != nil {
		return ""
	}
	return string(data)
}
