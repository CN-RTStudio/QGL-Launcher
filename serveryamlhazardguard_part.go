package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func yhCollect(root string) []string {
	found := []string{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return found
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		found = append(found, filepath.Join(root, name))
	}
	configDir := filepath.Join(root, "config")
	entries, err = os.ReadDir(configDir)
	if err != nil {
		return found
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		found = append(found, filepath.Join(configDir, name))
	}
	sort.Strings(found)
	return found
}

func yhInspectFile(a *YamlHazardAudit, root, path string) {
	rel, data, ok := inspectAuditTextFile(a.add, &a.Files, root, path, yhFileCheck)
	if !ok {
		return
	}
	yhScanText(a, rel, string(data))
}

func yhScanText(a *YamlHazardAudit, rel, text string) {
	lower := strings.ToLower(text)
	for _, tag := range yhApplyTags {
		if strings.Contains(lower, tag) {
			a.add(rel, yhReasonObjectApply, "YAML 使用可执行对象构造标签", true)
			break
		}
	}
	for _, tag := range yhUnsafeTags {
		if strings.Contains(lower, tag) {
			a.add(rel, yhReasonUnsafeTag, "YAML 包含外部类型标签", true)
			break
		}
	}
	if strings.Contains(lower, "!!binary") {
		a.add(rel, yhReasonBinaryBlob, "YAML 内嵌二进制块", false)
	}
	if strings.Contains(lower, "<<:") {
		a.add(rel, yhReasonMergeKey, "YAML 使用合并键引用", false)
	}
	if yhHasTabIndent(text) {
		a.add(rel, yhReasonTabIndent, "YAML 使用制表符缩进", false)
	}
	aliases := yhCountAliases(text)
	if aliases > yhMaxAliases {
		a.add(rel, yhReasonAliasBomb, fmt.Sprintf("YAML 别名引用 %d 次超过上限", aliases), true)
	}
	if yhMaxAliasDepth(text) > yhMaxDepth {
		a.add(rel, yhReasonAliasDepth, "YAML 锚点嵌套超过深度上限", true)
	}
	dups := yhDuplicateTopKeys(text)
	if dups > 0 {
		a.add(rel, yhReasonDuplicateKey, fmt.Sprintf("%d 个顶层键重复定义", dups), false)
	}
}
