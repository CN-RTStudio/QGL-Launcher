package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	packReasonOK           = "ok"
	packReasonMissing      = "missing"
	packReasonSymlink      = "symlink"
	packReasonUnreadable   = "unreadable"
	packReasonTooLarge     = "too-large"
	packReasonBadScheme    = "bad-scheme"
	packReasonInsecure     = "insecure-transport"
	packReasonUserinfo     = "url-userinfo"
	packReasonTooLong      = "url-too-long"
	packReasonBadHash      = "bad-hash"
	packReasonMissingHash  = "missing-hash"
	packReasonPlaceholder  = "placeholder-hash"
	packReasonBadPrompt    = "bad-prompt"
	packReasonDuplicateKey = "duplicate-key"
	packMaxURLLength       = 2048
	packMaxPromptRunes     = 256
	packSHA1HexLength      = 40
)

type PackFinding struct {
	Key      string
	Value    string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerResourcePackAudit struct {
	Path     string
	Present  bool
	PackURL  string
	Findings []PackFinding
}

func (a *ServerResourcePackAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f PackFinding) bool { return f.Blocking })
}

func (a *ServerResourcePackAudit) HasWarnings() bool {
	if a == nil {
		return false
	}
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != packReasonOK {
			return true
		}
	}
	return false
}

func (a *ServerResourcePackAudit) Codes() []string {
	if a == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(a.Findings))
	codes := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == packReasonOK {
			continue
		}
		if _, ok := seen[f.Reason]; ok {
			continue
		}
		seen[f.Reason] = struct{}{}
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}

func (a *ServerResourcePackAudit) Describe() string {
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == packReasonOK {
			continue
		}
		if f.Key == "" {
			parts = append(parts, fmt.Sprintf("%s: %s", f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%q(%s): %s", f.Key, f.Value, f.Reason, f.Detail))
	}
	return strings.Join(parts, "；")
}
