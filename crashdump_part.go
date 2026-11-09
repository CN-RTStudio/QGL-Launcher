package main

import (
	"path/filepath"
	"strings"
)

func safeCrashName(name string) string {
	name = filepath.Base(name)
	if name == "." || name == string(filepath.Separator) {
		return ""
	}
	return SanitizeFilename(name)
}

// looksLikeJavaException 粗判一行是否是顶层 Java 异常：
// 形如 "java.lang.IllegalStateException: ..." 或含全限定异常类型且带 Exception/Error。
func looksLikeJavaException(line string) bool {
	trim := strings.TrimSpace(line)
	if trim == "" || strings.HasPrefix(trim, "--") || strings.HasPrefix(trim, "at ") {
		return false
	}
	if !strings.Contains(trim, ".") {
		return false
	}
	return strings.Contains(trim, "Exception") || strings.Contains(trim, "Error") ||
		strings.Contains(trim, "Throwable")
}

// appendUnique 往切片追加不重复且有数量上限的字符串。
func appendUnique(list []string, s string, max int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return list
	}
	for _, existing := range list {
		if existing == s {
			return list
		}
	}
	if len(list) >= max {
		return list
	}
	return append(list, s)
}
