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

// InspectUpdateZip 只读预检更新包 zip：条目路径全部过 secureZipRelPath；
// 拒绝符号链接 / 设备条目；条目数与总大小设上限；记录是否存在单一顶层目录
// 与启动器可执行入口（*.exe / 二进制根文件）。不落盘任何内容。
