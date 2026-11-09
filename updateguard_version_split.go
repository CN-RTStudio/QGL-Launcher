package main

import (
	"errors"
	"strconv"
)

func numericToken(s string) (int64, bool) {
	if s == "" {
		return 0, true // 缺段视为数字 0
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// IsVersionNewer 判断候选版本是否比当前版本"更新"（语义比较）。
func IsVersionNewer(candidate, current string, limits UpdateLimits) (bool, error) {
	c := ParseVersionParts(candidate, limits)
	cur := ParseVersionParts(current, limits)
	if c == nil || cur == nil {
		return false, errors.New("版本号格式非法")
	}
	return CompareVersionTokens(c, cur) > 0, nil
}

// sanitizeUpdateDesc 校验更新说明：限长、拒绝控制字符。
func sanitizeUpdateDesc(desc string, limits UpdateLimits) (string, bool) {
	l := limits.withDefaults()
	if desc == "" {
		return desc, true
	}
	if len([]rune(desc)) > l.DescRunesMax {
		return "", false
	}
	for _, r := range desc {
		if r < 0x20 && r != '\n' && r != '\t' {
			return "", false
		}
	}
	return desc, true
}
