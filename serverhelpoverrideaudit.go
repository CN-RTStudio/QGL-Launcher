package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	hoReasonOK            = "ok"
	hoReasonMissing       = "missing"
	hoReasonUnreadable    = "unreadable"
	hoReasonSymlink       = "symlink"
	hoReasonTooLarge      = "too-large"
	hoReasonWorldWritable = "world-writable"
	hoReasonWorldReadable = "world-readable"
	hoReasonTooManyTopics = "too-many-topics"
	hoReasonTextTooLong   = "text-too-long"
	hoReasonControlChars  = "control-chars"
	hoReasonRemoteURL     = "remote-url"
	hoReasonWildcardPerm  = "wildcard-permission"
	hoReasonShadowTopic   = "shadowed-topic"
	hoReasonEmptyTopic    = "empty-topic"
	hoReasonDuplicateKey  = "duplicate-key"
	hoReasonUnknownField  = "unknown-field"
	hoReasonBadSection    = "bad-section"

	hoMaxFileBytes = 1 << 20
	hoMaxTopics    = 64
	hoMaxShortText = 256
	hoMaxFullText  = 4096
	hoMaxFindings  = 48
)

var hoConfigCandidates = []string{
	"help.yml",
	"config/help.yml",
}

var hoBuiltinTopics = []string{
	"help",
	"version",
	"plugins",
	"reload",
	"timings",
	"spark",
	"op",
	"deop",
}

var hoKnownSections = []string{
	"general-topics",
	"index-topics",
}

var hoKnownFields = []string{
	"shorttext",
	"fulltext",
	"permission",
}

type HelpOverrideFinding struct {
	File     string
	Topic    string
	Reason   string
	Detail   string
	Blocking bool
}

type HelpOverrideAudit struct {
	Dir      string
	Findings []HelpOverrideFinding
	Topics   int
}

func (a HelpOverrideAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f HelpOverrideFinding) bool { return f.Blocking })
}

func (a HelpOverrideAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f HelpOverrideFinding) bool { return !f.Blocking && f.Reason != hoReasonOK })
}

func (a HelpOverrideAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == hoReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail))
		if len(parts) >= hoMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务器帮助覆盖未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *HelpOverrideAudit) add(file, topic, reason, detail string, blocking bool) {
	if len(a.Findings) >= hoMaxFindings {
		return
	}
	a.Findings = append(a.Findings, HelpOverrideFinding{
		File:     file,
		Topic:    topic,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}
