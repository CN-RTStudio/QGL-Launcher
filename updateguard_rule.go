package main

import (
	"archive/zip"
	"errors"
	"io"
	"strconv"
)

func validateUpdateDescRune(r rune) bool {
	return !(r < 0x20 && r != '\n' && r != '\t')
}

func readZipEntryText(f *zip.File, maxBytes int64) (string, error) {
	if f.UncompressedSize64 > uint64(maxBytes) {
		return "", errors.New("条目超过读取上限")
	}
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	limited := io.LimitReader(rc, maxBytes+1)
	buf := make([]byte, 0, int(f.UncompressedSize64+1))
	tmp := make([]byte, 4096)
	for {
		n, err := limited.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if int64(len(buf)) > maxBytes {
			return "", errors.New("条目超过读取上限")
		}
	}
	// 控制字符检测（允许 \n \t）。
	for _, r := range string(buf) {
		if !validateUpdateDescRune(r) {
			return "", errors.New("条目含控制字符")
		}
	}
	return string(buf), nil
}

// 导出版本比较与 URL 校验的别名函数，供测试与调用方统一入口。
func ValidateUpdateUrl(raw string, limits UpdateLimits) (bool, string, string) {
	return sanitizeUpdateUrl(raw, limits)
}

func ValidateUpdateAssetName(name string, limits UpdateLimits) (string, bool) {
	return sanitizeUpdateAssetName(name, limits)
}

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
