package main

// langpackguard.go —— 启动器/资源包语言标签校验与归一。
//
// MC 资源包语言标签形如 zh_CN / en_US / zh-TW，由用户配置或服务器包元数据给入。
// 这个字符串会被拼进资源路径、写进日志、甚至送进远程统计。不校验就可能：
//
//   - 路径穿越（../../etc）；
//   - 控制字符/换行污染日志；
//   - 奇怪标签导致语言包查找 miss 后回退到英文却悄悄记了一笔。
//
// 这里只接受 [a-zA-Z]{2,8}(_[a-zA-Z0-9]{2,8}){0,1}，并归一为小写语言+大写地区。

import (
	"fmt"
	"strings"
)

// NormalizeLangTag 校验并归一语言标签。非法返回错误。
func NormalizeLangTag(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty lang tag")
	}
	if strings.ContainsAny(s, "/\\. \t\r\n") {
		return "", fmt.Errorf("illegal chars in lang tag: %q", s)
	}
	parts := strings.SplitN(s, "_", 2)
	lang := strings.ToLower(parts[0])
	if len(lang) < 2 || len(lang) > 8 {
		return "", fmt.Errorf("bad lang segment: %q", parts[0])
	}
	for _, c := range lang {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return "", fmt.Errorf("non-ascii in lang: %q", parts[0])
		}
	}
	if len(parts) == 1 {
		return lang, nil
	}
	region := strings.ToUpper(parts[1])
	if len(region) < 2 || len(region) > 8 {
		return "", fmt.Errorf("bad region segment: %q", parts[1])
	}
	for _, c := range region {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return "", fmt.Errorf("non-ascii in region: %q", parts[1])
		}
	}
	return lang + "_" + region, nil
}

// IsAcceptableLang 是便捷布尔入口。
func IsAcceptableLang(raw string) bool {
	_, err := NormalizeLangTag(raw)
	return err == nil
}
