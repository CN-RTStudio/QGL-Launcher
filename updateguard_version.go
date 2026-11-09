package main

import (
	"strings"
)

func ParseVersionParts(v string, limits UpdateLimits) [][]string {
	l := limits.withDefaults()
	if v == "" || len(v) > l.UrlLenMax/2 {
		return nil
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return nil
		}
	}
	raw := strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+'
	})
	if len(raw) == 0 || len(raw) > l.VersionParts {
		return nil
	}
	parts := make([][]string, 0, len(raw))
	for _, tok := range raw {
		if tok == "" {
			return nil
		}
		parts = append(parts, []string{tok})
	}
	return parts
}

// CompareVersionTokens 比较两个已拆好的版本 token 序列。
// 返回值 <0 / 0 / >0 对应 a<b / a==b / a>b。
// 规则：数字 token 数值比较（'9' < '10'）；字母 token 按 rune 字典序；
// 数字 token 整体小于字母 token；段数不同时缺段视为 0（数字）或空（字母）。
func CompareVersionTokens(a, b [][]string) int {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		var av, bv string
		if i < len(a) {
			av = a[i][0]
		}
		if i < len(b) {
			bv = b[i][0]
		}
		if av == bv {
			continue
		}
		aNum, aIsNum := numericToken(av)
		bNum, bIsNum := numericToken(bv)
		switch {
		case aIsNum && bIsNum:
			if aNum < bNum {
				return -1
			}
			if aNum > bNum {
				return 1
			}
		case aIsNum != bIsNum:
			if aIsNum {
				return -1
			}
			return 1
		default:
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}
