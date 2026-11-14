package main

import (
	"path/filepath"
	"strings"
)

func SafeModFileName(name string) (string, string) {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "", nameRejectEmpty
	}
	if why := auditComponent(base, maxModFileComponentLen); why != nameRejectNone {
		return "", why
	}
	lower := strings.ToLower(base)
	okExt := false
	for ext := range allowedModFileExts {
		if strings.HasSuffix(lower, ext) {
			okExt = true
			break
		}
	}
	if !okExt {
		return "", nameRejectExtension
	}
	return base, nameRejectNone
}

func PickSafeModFileName(candidates ...string) string {
	for _, c := range candidates {
		if clean, why := SafeModFileName(c); why == nameRejectNone {
			return clean
		}
	}
	return "mod.jar"
}

// describeNameReject 把拒绝原因码转成中文说明，供错误信息/安全事件使用。
