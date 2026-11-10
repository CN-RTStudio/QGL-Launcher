package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	pfReasonOK              = "ok"
	pfReasonMissing         = "missing"
	pfReasonUnreadable      = "unreadable"
	pfReasonSymlink         = "symlink"
	pfReasonTooLarge        = "too-large"
	pfReasonWorldWritable   = "world-writable"
	pfReasonWorldReadable   = "world-readable"
	pfReasonTooManyPacks    = "too-many-packs"
	pfReasonTooManyFilters  = "too-many-filters"
	pfReasonFilterAll       = "filter-covers-all"
	pfReasonEmptyNamespace  = "empty-namespace"
	pfReasonPathEscape      = "path-escape"
	pfReasonBadPattern      = "bad-pattern"
	pfReasonDuplicateFilter = "duplicate-filter"
	pfReasonWeakFormat      = "weak-pack-format"
	pfReasonDescLong        = "description-too-long"
	pfReasonUnknownKey      = "unknown-filter-key"
	pfReasonMalformedJSON   = "malformed-json"
	pfReasonEntryCap        = "entry-cap"

	pfMaxFileBytes = 256 << 10
	pfMaxPacks     = 64
	pfMaxFilters   = 64
	pfMaxDescChars = 1024
	pfMaxFindings  = 48
)

var pfPackRoots = []string{
	"datapacks",
	"world/datapacks",
}

type PackFilterFinding struct {
	Root     string
	Pack     string
	Reason   string
	Detail   string
	Blocking bool
}

type PackFilterAudit struct {
	Dir      string
	Findings []PackFilterFinding
	Packs    int
}

type pfMeta struct {
	Pack struct {
		PackFormat       json.RawMessage `json:"pack_format"`
		Description      json.RawMessage `json:"description"`
		SupportedFormats json.RawMessage `json:"supported_formats"`
		Filter           struct {
			Block     []pfFilterEntry `json:"block"`
			Namespace json.RawMessage `json:"namespace"`
		} `json:"filter"`
	} `json:"pack"`
}

type pfFilterEntry struct {
	Namespace string `json:"namespace"`
	Path      string `json:"path"`
}

func pfAuditMeta(audit *PackFilterAudit, root, pack string, raw []byte) {
	var meta pfMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		audit.add(root, pack, pfReasonMalformedJSON, "pack.mcmeta 无法解析", false)
		return
	}
	formatText := strings.Trim(string(meta.Pack.PackFormat), `"`)
	if formatText == "" || formatText == "null" {
		audit.add(root, pack, pfReasonWeakFormat, "缺少 pack_format", false)
	} else if formatText == "0" {
		audit.add(root, pack, pfReasonWeakFormat, "pack_format 为 0", false)
	}
	descText := strings.Trim(string(meta.Pack.Description), `"`)
	if len(descText) > pfMaxDescChars {
		audit.add(root, pack, pfReasonDescLong, fmt.Sprintf("描述 %d 字符", len(descText)), false)
	}
	blocks := meta.Pack.Filter.Block
	if len(blocks) > pfMaxFilters {
		audit.add(root, pack, pfReasonTooManyFilters, fmt.Sprintf("过滤规则 %d 条", len(blocks)), true)
	}
	seen := map[string]bool{}
	for _, entry := range blocks {
		ns := strings.TrimSpace(entry.Namespace)
		path := strings.TrimSpace(entry.Path)
		if ns == "" {
			audit.add(root, pack, pfReasonEmptyNamespace, "过滤规则缺少命名空间", true)
			continue
		}
		if ns == "*" && (path == "*" || path == "") {
			audit.add(root, pack, pfReasonFilterAll, "过滤规则覆盖全部数据包内容", true)
			continue
		}
		if pfEscapePattern(ns) || pfEscapePattern(path) {
			audit.add(root, pack, pfReasonPathEscape, "过滤规则含路径穿越 "+ns+":"+path, true)
		}
		if strings.Contains(ns, "*") {
			audit.add(root, pack, pfReasonBadPattern, "命名空间使用通配 "+ns, false)
		}
		if strings.Contains(path, "*") {
			audit.add(root, pack, pfReasonBadPattern, "路径使用通配 "+path, false)
		}
		key := ns + ":" + path
		if seen[key] {
			audit.add(root, pack, pfReasonDuplicateFilter, "重复过滤规则 "+key, false)
		}
		seen[key] = true
	}
	if len(meta.Pack.Filter.Namespace) > 0 && string(meta.Pack.Filter.Namespace) != "null" {
		audit.add(root, pack, pfReasonUnknownKey, "使用未知 filter.namespace 字段", false)
	}
}

func pfAuditPack(audit *PackFilterAudit, root, pack, dir string) {
	metaPath := filepath.Join(dir, "pack.mcmeta")
	info, err := os.Lstat(metaPath)
	if err != nil {
		audit.add(root, pack, pfReasonMissing, "缺少 pack.mcmeta", false)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(root, pack, pfReasonSymlink, "pack.mcmeta 是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(root, pack, pfReasonUnreadable, "pack.mcmeta 不是普通文件", true)
		return
	}
	if info.Size() > pfMaxFileBytes {
		audit.add(root, pack, pfReasonTooLarge, fmt.Sprintf("元数据 %d 字节", info.Size()), true)
		return
	}
	if info.Mode().Perm()&0o022 != 0 {
		audit.add(root, pack, pfReasonWorldWritable, fmt.Sprintf("权限 %#o 允许他人写入", info.Mode().Perm()), true)
	}
	if info.Mode().Perm()&0o004 != 0 {
		audit.add(root, pack, pfReasonWorldReadable, fmt.Sprintf("权限 %#o 允许他人读取", info.Mode().Perm()), false)
	}
	raw, readErr := readBoundedFile(metaPath, pfMaxFileBytes)
	if readErr != nil {
		audit.add(root, pack, pfReasonUnreadable, readErr.Error(), false)
		return
	}
	pfAuditMeta(audit, root, pack, raw)
}

func pfAuditRoot(audit *PackFilterAudit, root string) {
	path := filepath.Join(audit.Dir, filepath.FromSlash(root))
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			audit.add(root, "", pfReasonUnreadable, err.Error(), false)
		}
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(root, "", pfReasonSymlink, "数据包目录是符号链接", true)
		return
	}
	if !info.IsDir() {
		audit.add(root, "", pfReasonUnreadable, "数据包路径不是目录", true)
		return
	}
	entries, readErr := os.ReadDir(path)
	if readErr != nil {
		audit.add(root, "", pfReasonUnreadable, readErr.Error(), false)
		return
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		count++
		if count > pfMaxPacks {
			audit.add(root, "", pfReasonEntryCap, "数据包数量超出扫描上限", false)
			break
		}
		audit.Packs++
		pfAuditPack(audit, root, entry.Name(), filepath.Join(path, entry.Name()))
	}
	if count > pfMaxPacks {
		audit.add(root, "", pfReasonTooManyPacks, fmt.Sprintf("数据包 %d 个", count), true)
	}
}

func AuditServerDataPackFilters(serverDir string) PackFilterAudit {
	audit := PackFilterAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("server", "", pfReasonMissing, "服务器目录不可用", false)
		return audit
	}
	for _, root := range pfPackRoots {
		pfAuditRoot(&audit, root)
	}
	if audit.Packs == 0 {
		audit.add("datapacks", "", pfReasonOK, "未发现数据包", false)
	}
	return audit
}

func (a PackFilterAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PackFilterFinding) bool { return f.Blocking })
}
func (a PackFilterAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PackFilterFinding) bool { return !f.Blocking && f.Reason != pfReasonOK })
}
func (a PackFilterAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == pfReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s/%s:%s:%s", f.Root, f.Pack, f.Reason, f.Detail))
		if len(parts) >= pfMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "数据包过滤规则未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *PackFilterAudit) add(root, pack, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pfMaxFindings, PackFilterFinding{Root: root, Pack: pack, Reason: reason, Detail: detail, Blocking: blocking})
}

func pfEscapePattern(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return true
	}
	if strings.Contains(trimmed, "..") {
		return true
	}
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "\\") {
		return true
	}
	if strings.ContainsAny(trimmed, "\\\x00") {
		return true
	}
	return false
}
