package main

import (
	"fmt"
	"strings"
)

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
