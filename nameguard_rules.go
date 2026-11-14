package main

import (
	"strings"
)

func SafeVersionDisplayName(name string) (string, string) {
	clean := strings.TrimSpace(name)
	if why := auditComponent(clean, maxVersionDisplayLen); why != nameRejectNone {
		return "", why
	}
	return clean, nameRejectNone
}
func SafeLoaderComponent(value string) (string, string) {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return "", nameRejectEmpty
	}
	if why := auditComponent(clean, maxLoaderComponentLen); why != nameRejectNone {
		return "", why
	}
	// fabric / forge / 版本号这类加载器标识来自加载器元数据，是无空格的 token；
	// 内部空格只可能来自异常或伪造数据，拼进展示名 / 路径会引入歧义，单独拒绝。
	if strings.ContainsRune(clean, ' ') {
		return "", nameRejectInnerSpace
	}
	return clean, nameRejectNone
}
