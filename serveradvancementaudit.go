package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	adReasonOK              = "ok"
	adReasonMissing         = "missing"
	adReasonUnreadable      = "unreadable"
	adReasonSymlink         = "symlink"
	adReasonTooLarge        = "too-large"
	adReasonWorldWritable   = "world-writable"
	adReasonWorldReadable   = "world-readable"
	adReasonTooManyFiles    = "too-many-files"
	adReasonBadFileName     = "bad-file-name"
	adReasonMalformedJSON   = "malformed-json"
	adReasonDeepNesting     = "deep-nesting"
	adReasonDuplicateKey    = "duplicate-key"
	adReasonLootTraversal   = "loot-traversal"
	adReasonIconTraversal   = "icon-traversal"
	adReasonParentEscape    = "parent-escape"
	adReasonTooManyCriteria = "too-many-criteria"
	adReasonEmptyFile       = "empty-file"

	adMaxFileBytes = 2 << 20
	adMaxFiles     = 128
	adMaxDepth     = 32
	adMaxCriteria  = 64
	adMaxFindings  = 48
)

var adAdvancementDirs = []string{
	"world/advancements",
	"world_nether/advancements",
	"world_the_end/advancements",
}

var adFilePattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\.json$`)

type AdvancementFinding struct {
	Dir      string
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type AdvancementAudit struct {
	Dir      string
	Findings []AdvancementFinding
	Files    int
}

func (a AdvancementAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a AdvancementAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != adReasonOK {
			return true
		}
	}
	return false
}

func (a AdvancementAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == adReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.Dir, f.Reason, f.Detail))
		if len(parts) >= adMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务器进度数据未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *AdvancementAudit) add(dir, file, reason, detail string, blocking bool) {
	if len(a.Findings) >= adMaxFindings {
		return
	}
	a.Findings = append(a.Findings, AdvancementFinding{
		Dir:      dir,
		File:     file,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}

func adJSONDepth(data []byte) int {
	depth := 0
	max := 0
	inString := false
	escaped := false
	for _, b := range data {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > max {
				max = depth
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return max
}

func adDuplicateKeys(data []byte) []string {
	dups := []string{}
	seen := map[string]int{}
	text := string(data)
	for {
		idx := strings.Index(text, "\"")
		if idx < 0 {
			break
		}
		rest := text[idx+1:]
		end := strings.Index(rest, "\"")
		if end < 0 {
			break
		}
		key := rest[:end]
		after := strings.TrimLeft(rest[end+1:], " \t\r\n")
		if strings.HasPrefix(after, ":") {
			seen[key]++
			if seen[key] == 2 {
				dups = append(dups, key)
			}
		}
		text = rest[end+1:]
	}
	return dups
}

func adUnsafeResource(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return true
	}
	if strings.HasPrefix(trimmed, "/") {
		return true
	}
	if strings.Contains(trimmed, "..") {
		return true
	}
	if strings.ContainsAny(trimmed, "\\\x00") {
		return true
	}
	return false
}

func adAuditPayload(audit *AdvancementAudit, dir, name string, raw []byte) {
	var decoded struct {
		Criteria     map[string]json.RawMessage `json:"criteria"`
		Requirements json.RawMessage            `json:"requirements"`
		Parent       string                     `json:"parent"`
		Rewards      struct {
			Loot    []string `json:"loot"`
			Recipes []string `json:"recipes"`
		} `json:"rewards"`
		Display struct {
			Icon  json.RawMessage `json:"icon"`
			Title json.RawMessage `json:"title"`
			Frame string          `json:"frame"`
		} `json:"display"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		if adJSONDepth(raw) > adMaxDepth {
			audit.add(dir, name, adReasonDeepNesting, fmt.Sprintf("嵌套深度 %d", adJSONDepth(raw)), true)
			return
		}
		audit.add(dir, name, adReasonMalformedJSON, "进度文件无法解析", false)
		return
	}
	if len(decoded.Criteria) > adMaxCriteria {
		audit.add(dir, name, adReasonTooManyCriteria, fmt.Sprintf("criteria %d 条", len(decoded.Criteria)), false)
	}
	for _, loot := range decoded.Rewards.Loot {
		if adUnsafeResource(loot) {
			audit.add(dir, name, adReasonLootTraversal, "奖励战利品路径异常 "+loot, true)
		}
	}
	for _, recipe := range decoded.Rewards.Recipes {
		if adUnsafeResource(recipe) {
			audit.add(dir, name, adReasonLootTraversal, "奖励配方路径异常 "+recipe, true)
		}
	}
	icon := strings.Trim(string(decoded.Display.Icon), `"`)
	if icon != "" && adUnsafeResource(icon) {
		audit.add(dir, name, adReasonIconTraversal, "图标路径异常 "+icon, true)
	}
	if decoded.Parent != "" && adUnsafeResource(decoded.Parent) {
		audit.add(dir, name, adReasonParentEscape, "父进度路径异常 "+decoded.Parent, false)
	}
	for _, key := range adDuplicateKeys(raw) {
		audit.add(dir, name, adReasonDuplicateKey, "重复键 "+key, false)
	}
}

func adAuditDir(audit *AdvancementAudit, rel string) {
	path := filepath.Join(audit.Dir, filepath.FromSlash(rel))
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			audit.add(rel, "", adReasonUnreadable, err.Error(), false)
		}
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(rel, "", adReasonSymlink, "进度目录是符号链接", true)
		return
	}
	if !info.IsDir() {
		audit.add(rel, "", adReasonUnreadable, "进度路径不是目录", true)
		return
	}
	entries, readErr := os.ReadDir(path)
	if readErr != nil {
		audit.add(rel, "", adReasonUnreadable, readErr.Error(), false)
		return
	}
	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		count++
		if count > adMaxFiles {
			audit.add(rel, "", adReasonTooManyFiles, fmt.Sprintf("进度文件 %d 个", count), true)
			break
		}
		audit.Files++
		info, infoErr := entry.Info()
		if infoErr != nil {
			audit.add(rel, name, adReasonUnreadable, infoErr.Error(), false)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(rel, name, adReasonSymlink, "进度文件是符号链接", true)
			continue
		}
		if !info.Mode().IsRegular() {
			audit.add(rel, name, adReasonUnreadable, "进度文件不是普通文件", true)
			continue
		}
		if !adFilePattern.MatchString(name) {
			audit.add(rel, name, adReasonBadFileName, "文件名不是标准 UUID", false)
		}
		if info.Size() > adMaxFileBytes {
			audit.add(rel, name, adReasonTooLarge, fmt.Sprintf("进度文件 %d 字节", info.Size()), true)
			continue
		}
		if info.Mode().Perm()&0o022 != 0 {
			audit.add(rel, name, adReasonWorldWritable, fmt.Sprintf("权限 %#o 允许他人写入", info.Mode().Perm()), true)
		}
		raw, readErr := readBoundedFile(filepath.Join(path, name), adMaxFileBytes)
		if readErr != nil {
			audit.add(rel, name, adReasonUnreadable, readErr.Error(), false)
			continue
		}
		if depth := adJSONDepth(raw); depth > adMaxDepth {
			audit.add(rel, name, adReasonDeepNesting, fmt.Sprintf("嵌套深度 %d", depth), true)
			continue
		}
		adAuditPayload(audit, rel, name, raw)
	}
}

func AuditServerAdvancements(serverDir string) AdvancementAudit {
	audit := AdvancementAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("server", "", adReasonMissing, "服务器目录不可用", false)
		return audit
	}
	for _, rel := range adAdvancementDirs {
		adAuditDir(&audit, rel)
	}
	if audit.Files == 0 {
		audit.add("world/advancements", "", adReasonOK, "未发现玩家进度文件", false)
	}
	return audit
}
