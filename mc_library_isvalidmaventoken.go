package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func isValidMavenToken(token string) bool {
	if token == "" || token == "." || token == ".." {
		return false
	}
	if len(token) > 255 {
		return false
	}
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			// 字母数字
		case strings.ContainsRune("-_.@+", r):
			// Maven 常见合法字符
		default:
			return false
		}
	}
	return true
}
func mavenNameToPath(name string, libsDir string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}
	// 坐标的每一段都必须是干净的 Maven token；groupId 的每个 "." 分段也要
	// 单独校验，否则 "..\.." 之类会在 ReplaceAll 之后变成路径穿越。
	groupParts := strings.Split(parts[0], ".")
	for _, seg := range groupParts {
		if !isValidMavenToken(seg) {
			return ""
		}
	}
	artifact, version := parts[1], parts[2]
	if !isValidMavenToken(artifact) || !isValidMavenToken(version) {
		return ""
	}
	classifier := ""
	if len(parts) >= 4 {
		if !isValidMavenToken(parts[3]) {
			return ""
		}
		classifier = "-" + parts[3]
	}
	group := strings.Join(groupParts, string(os.PathSeparator))
	fileName := fmt.Sprintf("%s-%s%s.jar", artifact, version, classifier)
	rel := filepath.Join(group, artifact, version, fileName)
	// 拼好后再用统一的相对路径校验兜底，确保结果一定在 libraries 内。
	if isSafeRelPath(rel) == "" {
		return ""
	}
	return filepath.Join(libsDir, rel)
}

func (a *App) buildClasspath(mcDir string, versionID string, versionJSON *VersionJSON) []string {
	var entries []string
	libsDir := filepath.Join(mcDir, "libraries")
	for _, lib := range versionJSON.Libraries {
		if !a.shouldIncludeLib(lib) || lib.Natives != nil {
			continue
		}
		var libPath string
		if lib.Downloads != nil && lib.Downloads.Artifact != nil && lib.Downloads.Artifact.Path != "" {
			safePath := isSafeRelPath(lib.Downloads.Artifact.Path)
			if safePath == "" {
				continue
			}
			libPath = filepath.Join(libsDir, safePath)
		} else if lib.JarPath != "" {
			// lib.JarPath 是镜像 JSON 直接给的相对路径，必须校验，
			// 否则恶意条目可以把 libraries 之外的任意 jar 塞进启动 classpath。
			safeJarPath := isSafeRelPath(lib.JarPath)
			if safeJarPath == "" {
				continue
			}
			libPath = filepath.Join(libsDir, safeJarPath)
		} else if lib.Name != "" {
			libPath = mavenNameToPath(lib.Name, libsDir)
		}
		if libPath == "" {
			continue
		}
		if state := inspectRegularFile(libPath); !state.trustable() {
			if state.Exists {
				recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
					"classpath", describeUntrustedFile(state, libPath))
			}
			continue
		}
		entries = append(entries, libPath)
	}
	// Jar / InheritsFrom 来自外部版本 JSON，会拼进 versions/<name>/<name>.jar，
	// 必须逐个收敛成单段安全名；三者都非法时跳过该 classpath 条目而不是拼出穿越路径。
	jarName := ""
	for _, c := range []string{versionJSON.Jar, versionJSON.InheritsFrom, versionID} {
		if s := safeVersionName(c); s != "" {
			jarName = s
			break
		}
	}
	if jarName != "" {
		versionJar := filepath.Join(mcDir, "versions", jarName, jarName+".jar")
		if !inspectRegularFile(versionJar).trustable() {
			if self := safeVersionName(versionID); self != "" {
				altJar := filepath.Join(mcDir, "versions", self, self+".jar")
				if inspectRegularFile(altJar).trustable() {
					versionJar = altJar
				}
			}
		}
		entries = append(entries, versionJar)
	}
	return entries
}
