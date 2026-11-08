package main

import (
	"fmt"
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
	return anyBlocking(a.Findings, func(f YamlHazardFinding) bool { return f.Blocking })
}

func (a YamlHazardAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f YamlHazardFinding) bool { return !f.Blocking && f.Reason != yhReasonOK })
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
