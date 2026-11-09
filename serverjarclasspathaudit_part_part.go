package main

import (
	"fmt"
	"strings"
)

func jarCPHasTraversal(entry string) bool {
	normalized := strings.ReplaceAll(entry, `\\`, "/")
	for _, seg := range strings.Split(normalized, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

func jarCPScanManifest(audit *JarClassPathAudit, jar string, data []byte) bool {
	lines := jarCPUnfoldManifest(data)
	classPath := ""
	agent := false
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, jarCpClassPathAttr) {
			classPath = strings.TrimSpace(line[len(jarCpClassPathAttr):])
		}
		if strings.HasPrefix(lower, "premain-class:") || strings.HasPrefix(lower, "agent-class:") {
			agent = true
		}
		if strings.HasPrefix(lower, "launcher-agent-class:") {
			agent = true
		}
	}
	if agent {
		audit.add(jar, "manifest", jarCpReasonAgentEntry, "jar 声明了 java agent 入口，需确认来源可信", false)
	}
	if classPath == "" {
		return false
	}
	entries := jarCPEntries(classPath)
	if len(entries) > jarCpMaxEntries {
		audit.add(jar, "class-path", jarCpReasonTooMany, fmt.Sprintf("Class-Path 条目数量 %d 超过上限", len(entries)), true)
	}
	seen := map[string]bool{}
	flagged := 0
	for _, entry := range entries {
		if seen[entry] {
			audit.add(jar, entry, jarCpReasonDuplicate, "Class-Path 重复条目", false)
			flagged++
			continue
		}
		seen[entry] = true
		switch {
		case jarCPIsRemote(entry):
			audit.add(jar, entry, jarCpReasonRemote, "Class-Path 指向远程或 file 协议，可加载任意路径", true)
		case jarCPIsAbsolute(entry):
			audit.add(jar, entry, jarCpReasonAbsolute, "Class-Path 使用绝对路径，可逃逸服务器目录", true)
		case jarCPHasTraversal(entry):
			audit.add(jar, entry, jarCpReasonTraversal, "Class-Path 包含 .. 片段，可逃逸服务器目录", true)
		}
		flagged++
		if flagged >= jarCpMaxFindingsPerJar {
			audit.add(jar, "class-path", jarCpReasonTooMany, "单 jar Class-Path 告警过多，后续条目未展开", false)
			break
		}
	}
	return true
}
