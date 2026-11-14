package main

import (
	"strings"
)

const (
	// minTranslateQueryRunes 有效查询至少 1 个非空白字符。
	minTranslateQueryRunes = 1
	// maxTranslateQueryRunes 查询最长按 rune 计（与历史 capTranslateInput 对齐）。
	maxTranslateQueryRunes = 1024
	// maxChineseSearchResults 中文模糊搜索单次返回的硬上限，防止极短词命中全表
	// 后把数千条结果一次性经 IPC 推给渲染层。
	maxChineseSearchResults = 200
)

// stripControlRunes 移除 ASCII 控制字符（0x00-0x1F 与 0x7F），保留正常空白
// （空格等）交给后续 TrimSpace 处理。按 rune 遍历避免截断多字节中文。
func stripControlRunes(s string) string {
	if !strings.ContainsAny(s, controlProbeSet) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0x7f || (r >= 0x00 && r <= 0x1f) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// controlProbeSet 仅用于快速预判字符串是否可能含控制字符，避免常见无控制字符
// 的输入分配 Builder。
const controlProbeSet = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" +
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f"

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
