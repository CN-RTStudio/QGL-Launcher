package main

import (
	"fmt"
	"strings"
)

// manifestHasCritical 判断问题集中是否含 critical。
func manifestHasCritical(findings []ManifestFinding) bool {
	for i := range findings {
		if findings[i].Severity == manifestCritical {
			return true
		}
	}
	return false
}

// manifestCriticalError 把 critical 问题汇总成一个可返回的错误，只带字段名与
// 固定说明，不拼接外部可控字符串。
func manifestCriticalError(findings []ManifestFinding) error {
	n := 0
	fields := make([]string, 0, 8)
	for i := range findings {
		if findings[i].Severity != manifestCritical {
			continue
		}
		n++
		if len(fields) < 8 {
			fields = append(fields, findings[i].Field)
		}
	}
	if n == 0 {
		return nil
	}
	return fmt.Errorf("版本清单存在 %d 处严重安全问题，已拒绝下载（涉及字段: %s）", n, strings.Join(fields, ", "))
}

// safeVersionName 校验版本 / 继承父版本的目录名。与资源索引 ID 走的严格 Maven
// 字符集不同：自定义版本名允许空格、中文等（sanitizeVersionName 也保留它们），
// 这里只做“越出 versions/ 目录”所需的最小约束——拒分隔符（/ \）、冒号（盘符 /
// NTFS ADS）、NUL 与控制字符、空段、"."/".."。没有分隔符时，名字里出现 ".."
// 子串（如 "1.0..2"）仍是 versions/ 下的单段目录，不构成穿越。
func safeVersionName(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 256 {
		return ""
	}
	if s == "." || s == ".." || strings.ContainsAny(s, `/\:`) {
		return ""
	}
	for _, r := range s {
		if r == 0 || r < 0x20 {
			return ""
		}
	}
	return s
}

// validateInheritStep 校验 inheritsFrom 链上的下一步：父 ID 必须是安全的单段版本名
// （拒盘符 / 分隔符 / "." / ".." 穿越），深度受限，且不允许成环。
// 返回清洗后的父 ID。
func validateInheritStep(parentID string, depth int, seen map[string]bool) (string, error) {
	if depth >= maxManifestInheritDepth {
		return "", fmt.Errorf("版本继承链超过 %d 层，疑似恶意嵌套", maxManifestInheritDepth)
	}
	safe := safeVersionName(parentID)
	if safe == "" {
		return "", fmt.Errorf("inheritsFrom 不是合法的单段版本名，拒绝解析")
	}
	if seen[safe] {
		return "", fmt.Errorf("版本继承链存在循环引用，拒绝解析")
	}
	return safe, nil
}
