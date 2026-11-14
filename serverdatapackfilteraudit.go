package main

import (
	"encoding/json"
	"fmt"
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
