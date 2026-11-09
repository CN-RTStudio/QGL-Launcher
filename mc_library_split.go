package main

import (
	"path/filepath"
)

func (a *App) mergeVersionJSON(parent *VersionJSON, child *VersionJSON) VersionJSON {
	merged := *parent
	if child.ID != "" {
		merged.ID = child.ID
	}
	if child.MainClass != "" {
		merged.MainClass = child.MainClass
	}
	if child.Type != "" {
		merged.Type = child.Type
	}
	if child.ReleaseTime != "" {
		merged.ReleaseTime = child.ReleaseTime
	}
	if child.Jar != "" {
		merged.Jar = child.Jar
	}
	childGroupArtifacts := map[string]bool{}
	for _, lib := range child.Libraries {
		childGroupArtifacts[libGroupArtifact(lib.Name)] = true
	}
	var mergedLibs []Library
	for _, lib := range parent.Libraries {
		if !childGroupArtifacts[libGroupArtifact(lib.Name)] {
			mergedLibs = append(mergedLibs, lib)
		}
	}
	mergedLibs = append(mergedLibs, child.Libraries...)
	merged.Libraries = mergedLibs
	if child.MinecraftArgs != "" {
		merged.MinecraftArgs = child.MinecraftArgs
	}
	if child.Arguments != nil {
		if merged.Arguments == nil {
			merged.Arguments = &ArgumentsObj{}
		}
		if len(child.Arguments.JVM) > 0 {
			merged.Arguments.JVM = append(merged.Arguments.JVM, child.Arguments.JVM...)
		}
		if len(child.Arguments.Game) > 0 {
			merged.Arguments.Game = append(merged.Arguments.Game, child.Arguments.Game...)
		}
	}
	if child.Downloads != nil {
		merged.Downloads = child.Downloads
	}
	if child.AssetIndex != nil {
		merged.AssetIndex = child.AssetIndex
	}
	merged.InheritsFrom = child.InheritsFrom
	return merged
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
