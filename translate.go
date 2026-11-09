package main

import (
	"bufio"
	"embed"
	"sort"
	"strings"
	"sync"
)

//go:embed resources/ModData.txt
var modDataFile embed.FS

type ModTranslationEntry struct {
	English string `json:"english"`
	Chinese string `json:"chinese"`
}

// prefixRule 是前缀匹配的一条规则，loadTranslations 时按前缀长度降序排好，
// 这样多前缀同时命中时永远命中最长的那个，结果确定可复现。
type prefixRule struct {
	prefix  string
	chinese string
}

const maxTranslateInputRunes = 1024

var (
	translationEntries []ModTranslationEntry
	containsEntries    []ModTranslationEntry // 只有精确条目（不带 @），给 contains 匹配用
	exactTranslations  map[string]string
	prefixTranslations []prefixRule
	translationLoaded  bool
	translationMutex   sync.RWMutex
)

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

	exactTranslations = make(map[string]string)
	prefixTranslations = nil
	containsEntries = nil

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Split(line, "¨")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			idx := strings.Index(part, "|")
			if idx <= 0 || idx >= len(part)-1 {
				continue
			}
			english := strings.TrimSpace(part[:idx])
			chinese := strings.TrimSpace(part[idx+1:])
			if english == "" || chinese == "" {
				continue
			}

			translationEntries = append(translationEntries, ModTranslationEntry{
				English: english,
				Chinese: chinese,
			})

			lowerEnglish := strings.ToLower(english)
			if strings.HasSuffix(english, "@") {
				prefix := strings.ToLower(english[:len(english)-1])
				prefixTranslations = append(prefixTranslations, prefixRule{prefix: prefix, chinese: chinese})
			} else {
				exactTranslations[lowerEnglish] = chinese
				containsEntries = append(containsEntries, ModTranslationEntry{
					English: lowerEnglish,
					Chinese: chinese,
				})
			}
		}
	}

	// 前缀按长度降序：长前缀优先命中，保证确定性。
	sort.Slice(prefixTranslations, func(i, j int) bool {
		if len(prefixTranslations[i].prefix) != len(prefixTranslations[j].prefix) {
			return len(prefixTranslations[i].prefix) > len(prefixTranslations[j].prefix)
		}
		return prefixTranslations[i].prefix < prefixTranslations[j].prefix
	})

	// contains 条目也按 key 长度降序，长的优先命中。
	sort.Slice(containsEntries, func(i, j int) bool {
		if len(containsEntries[i].English) != len(containsEntries[j].English) {
			return len(containsEntries[i].English) > len(containsEntries[j].English)
		}
		return containsEntries[i].English < containsEntries[j].English
	})
}

// capTranslateInput 限制输入长度，避免恶意输入把 contains 全表扫描打爆。
