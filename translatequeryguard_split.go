package main

import (
	"strings"
)

// normalizeTranslateQuery 规范化译名查询：先按 rune 限长，再剔除控制字符，最后
// 去首尾空白。返回 ok=false 表示查询为空 / 全空白 / 短于最小长度，调用方应直接
// 返回空结果而不是扫全表。
func normalizeTranslateQuery(raw string) (string, bool) {
	runes := []rune(raw)
	if len(runes) > maxTranslateQueryRunes {
		runes = runes[:maxTranslateQueryRunes]
	}
	clean := stripControlRunes(string(runes))
	clean = strings.TrimSpace(clean)
	if len([]rune(clean)) < minTranslateQueryRunes {
		return "", false
	}
	return clean, true
}

// appendDistinctOrdered 向结果集追加一个去重后的值，并强制硬上限。
// 返回追加后的切片，以及是否已经达到上限（调用方据此立即停止全表扫描）。
// seen 由调用方在一次查询内复用，保证 O(1) 判重。
func appendDistinctOrdered(list []string, seen map[string]struct{}, value string, max int) ([]string, bool) {
	if max <= 0 {
		return list, true
	}
	if _, dup := seen[value]; dup {
		return list, false
	}
	seen[value] = struct{}{}
	list = append(list, value)
	if len(list) >= max {
		return list, true
	}
	return list, false
}
