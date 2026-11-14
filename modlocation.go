package main

import (
	"strings"
)

const (
	modsDirSegment    = "mods"
	versionsSegment   = "versions"
	disabledJarSuffix = ".jar.disabled"
	jarSuffix         = ".jar"
)

// modNameLooksSafe 校验 Mod 文件名本身：非空、单段名（不含分隔符；调用方已按
// os.PathSeparator 切分，这里再兜一次正斜杠）、不含 NUL/控制字符、不是 "."/".."，
// 且结尾不是 Win32 会吞掉的点或空格。
func modNameLooksSafe(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] == 0 || name[i] < 0x20 {
			return false
		}
	}
	return true
}

// isModJarName 报告文件名是否为受管的 jar（启用）或已禁用 jar（.jar.disabled）。
// 扩展名大小写不敏感，与 GetModList / ToggleMod 的既有口径一致。
func isModJarName(name string) bool {
	if !modNameLooksSafe(name) {
		return false
	}
	lower := strings.ToLower(name)
	// ".jar" 与 ".jar.disabled" 两种后缀互斥（后者结尾是 ".disabled"）。
	return strings.HasSuffix(lower, jarSuffix) || strings.HasSuffix(lower, disabledJarSuffix)
}
