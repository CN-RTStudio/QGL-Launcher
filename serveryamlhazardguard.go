package main

import (
	"fmt"
	"strings"
)

const (
	yhReasonOK            = "ok"
	yhReasonSymlink       = "symlink"
	yhReasonTooLarge      = "too-large"
	yhReasonWorldWritable = "world-writable"
	yhReasonUnreadable    = "unreadable"
	yhReasonTooManyFiles  = "file-overflow"
	yhReasonUnsafeTag     = "unsafe-tag"
	yhReasonObjectApply   = "object-apply"
	yhReasonBinaryBlob    = "binary-blob"
	yhReasonAliasBomb     = "alias-bomb"
	yhReasonAliasDepth    = "alias-depth"
	yhReasonTabIndent     = "tab-indent"
	yhReasonDuplicateKey  = "duplicate-key"
	yhReasonMergeKey      = "merge-key"

	yhMaxFiles    = 32
	yhMaxBytes    = 1 << 20
	yhMaxAliases  = 48
	yhMaxDepth    = 8
	yhMaxFindings = 48
)

var yhUnsafeTags = []string{
	"!!javax",
	"!!java.",
	"!!com.sun",
	"!!java.net",
	"!!ruby/object",
	"!!python/object",
	"!!python/name",
	"!<tag:yaml.org,2002:javax",
	"!!org.springframework",
	"!!org.apache",
}

var yhApplyTags = []string{
	"!!python/object/apply",
	"!!python/object/new",
	"!!javax.script.scriptenginemanager",
	"!!java.lang.runtime",
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

func yhHasTabIndent(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "\t") {
			return true
		}
		if strings.HasPrefix(line, " \t") {
			return true
		}
	}
	return false
}

func yhCountAliases(text string) int {
	count := 0
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		colon := strings.Index(trimmed, ":")
		if colon >= 0 {
			value := strings.TrimSpace(trimmed[colon+1:])
			if strings.HasPrefix(value, "*") {
				count++
				continue
			}
		}
		if strings.HasPrefix(trimmed, "- *") {
			count++
		}
	}
	return count
}
