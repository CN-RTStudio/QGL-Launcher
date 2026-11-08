package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

type YamlHazardFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type YamlHazardAudit struct {
	Dir      string
	Files    []string
	Findings []YamlHazardFinding
}

func (a YamlHazardAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a YamlHazardAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != yhReasonOK {
			return true
		}
	}
	return false
}

func (a YamlHazardAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == yhReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "yaml"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= yhMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "YAML 配置未发现构造风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *YamlHazardAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= yhMaxFindings {
		return
	}
	a.Findings = append(a.Findings, YamlHazardFinding{
		File:     file,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}

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
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	rel, relErr := filepath.Rel(root, path)
	if relErr != nil {
		rel = filepath.Base(path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(rel, yhReasonSymlink, "YAML 配置是符号链接", true)
		return
	}
	if info.Size() > yhMaxBytes {
		a.add(rel, yhReasonTooLarge, "YAML 配置超过体积预算", true)
		return
	}
	if info.Mode().Perm()&0o022 != 0 {
		a.add(rel, yhReasonWorldWritable, "YAML 配置可被其他用户改写", true)
	}
	data, readErr := readBoundedFile(path, yhMaxBytes)
	if readErr != nil {
		a.add(rel, yhReasonUnreadable, "YAML 配置不可读", true)
		return
	}
	a.Files = append(a.Files, rel)
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

func yhMaxAliasDepth(text string) int {
	anchors := 0
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "&") {
			parts := strings.SplitN(trimmed, "&", 2)
			if len(parts) == 2 && parts[1] != "" && !strings.HasPrefix(parts[1], "amp;") {
				anchors++
			}
		}
		if strings.Count(trimmed, "*") > 0 && strings.Contains(trimmed, ":") {
			value := strings.TrimSpace(trimmed[strings.Index(trimmed, ":")+1:])
			if strings.HasPrefix(value, "*") {
				anchors++
			}
		}
	}
	return anchors
}

func yhDuplicateTopKeys(text string) int {
	counts := map[string]int{}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			continue
		}
		colon := strings.Index(trimmed, ":")
		if colon <= 0 {
			continue
		}
		key := strings.ToLower(strings.Trim(strings.TrimSpace(trimmed[:colon]), `"'`))
		if key == "" {
			continue
		}
		counts[key]++
	}
	dups := 0
	for _, n := range counts {
		if n > 1 {
			dups++
		}
	}
	return dups
}

func AuditServerYamlHazards(serverDir string) YamlHazardAudit {
	audit := YamlHazardAudit{Dir: serverDir}
	root, err := filepath.Abs(serverDir)
	if err != nil {
		audit.add("server-dir", yhReasonUnreadable, "无法解析服务器目录", true)
		return audit
	}
	audit.Dir = root
	info, statErr := os.Lstat(root)
	if statErr != nil || !info.IsDir() {
		audit.add("server-dir", yhReasonUnreadable, "服务器目录不存在", true)
		return audit
	}
	files := yhCollect(root)
	if len(files) > yhMaxFiles {
		audit.add("yaml", yhReasonTooManyFiles, fmt.Sprintf("YAML 文件 %d 个超过扫描上限", len(files)), false)
		files = files[:yhMaxFiles]
	}
	for _, path := range files {
		yhInspectFile(&audit, root, path)
	}
	if len(audit.Findings) == 0 {
		audit.add("yaml", yhReasonOK, "YAML 配置均在白名单结构内", false)
	}
	return audit
}
