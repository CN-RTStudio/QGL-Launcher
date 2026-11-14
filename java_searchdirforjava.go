package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func searchDirForJava(dir string, results *[]JavaEntry, seen map[string]bool, maxDepth int) {
	if maxDepth <= 0 {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	// 关键字列表（参考PCL）
	keywords := []string{
		"java", "jdk", "jre", "runtime", "env", "run", "soft",
		"corretto", "adoptium", "zulu", "semeru", "microsoft",
		"eclipse", "oracle", "hotspot", "openjdk", "bellsoft",
		"program", "game", "mc", "minecraft", "version",
		"x64", "x86", "bin", "users",
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		lowerName := strings.ToLower(name)

		// 检查 bin 目录下是否有 javaw.exe
		javawPath := filepath.Join(dir, name, "bin", "javaw.exe")
		if _, err := os.Stat(javawPath); err == nil && !seen[javawPath] {
			seen[javawPath] = true
			javaEntry := validateJava(javawPath)
			if javaEntry != nil {
				*results = append(*results, *javaEntry)
			}
		}

		// 决定是否进入子目录
		shouldEnter := false
		// 数字开头的目录（版本号）
		if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
			shouldEnter = true
		}
		// bin 目录无条件进入
		if lowerName == "bin" {
			shouldEnter = true
		}
		// users 目录无条件进入
		if lowerName == "users" {
			shouldEnter = true
		}
		// 关键字匹配
		if !shouldEnter {
			for _, kw := range keywords {
				if strings.Contains(lowerName, kw) {
					shouldEnter = true
					break
				}
			}
		}

		if shouldEnter {
			searchDirForJava(filepath.Join(dir, name), results, seen, maxDepth-1)
		}
	}
}

// validateJava 验证 Java 路径并获取版本信息（参考PCL的JavaEntry.Check）
func validateJava(javawPath string) *JavaEntry {
	// 检查 javaw.exe 是否存在
	if _, err := os.Stat(javawPath); err != nil {
		return nil
	}

	// 检查 java.exe 是否存在（同目录下）
	dir := filepath.Dir(javawPath)
	javaExePath := filepath.Join(dir, "java.exe")
	if _, err := os.Stat(javaExePath); err != nil {
		return nil
	}

	// 判断是否为 JDK（检查 javac.exe）
	javacPath := filepath.Join(dir, "javac.exe")
	isJDK := false
	if _, err := os.Stat(javacPath); err == nil {
		isJDK = true
	}

	// 运行 java -version 获取版本信息
	cmd := exec.Command(javaExePath, "-version")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 某些 Java 即使成功也会返回非零退出码
		// 尝试解析输出
	}

	outputStr := string(output)

	// 解析版本号（参考PCL的正则匹配逻辑）
	version, majorVer := parseJavaVersion(outputStr)
	if majorVer <= 0 {
		return nil
	}

	// 检测是否为64位
	is64Bit := strings.Contains(outputStr, "64-Bit") || strings.Contains(outputStr, "64-bit")

	return &JavaEntry{
		Path:     javawPath,
		Version:  version,
		MajorVer: majorVer,
		Is64Bit:  is64Bit,
		IsJDK:    isJDK,
	}
}

// parseJavaVersion 从 java -version 输出中解析版本号
