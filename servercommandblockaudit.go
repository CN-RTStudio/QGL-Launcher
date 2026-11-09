package main

import (
	"fmt"
	"strings"
)

const (
	scbMaxFindings      = 48
	scbMaxProps         = 256 * 1024
	scbMaxYAML          = 512 * 1024
	scbDefaultChainMax  = 65536
	scbHardChainMax     = 262144
	scbDefaultForkMax   = 256
	scbHardForkMax      = 1024
	scbReasonOK         = "ok"
	scbReasonMissing    = "missing"
	scbReasonSymlink    = "symlink"
	scbReasonTooLarge   = "too-large"
	scbReasonUnreadable = "unreadable"
	scbReasonBadValue   = "bad-value"
	scbReasonChainLong  = "command-chain-too-long"
	scbReasonForkHigh   = "command-fork-too-high"
	scbReasonOpHigh     = "op-level-maximum"
	scbReasonFnHigh     = "function-level-maximum"
	scbReasonRCECombo   = "command-block-rce-surface"
	scbReasonSilent     = "silent-commandblock-console"
	scbReasonNoBlock    = "command-block-disabled"
	scbReasonSpamList   = "spam-exclusion-widened"
)

type CommandBlockFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type CommandBlockAudit struct {
	ServerDir string
	Findings  []CommandBlockFinding
}

func (a *CommandBlockAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= scbMaxFindings {
		return
	}
	a.Findings = append(a.Findings, CommandBlockFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *CommandBlockAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CommandBlockFinding) bool { return f.Blocking })
}

func (a *CommandBlockAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if f.Reason != scbReasonOK && !f.Blocking {
			return true
		}
	}
	return false
}

func (a *CommandBlockAudit) Describe() string {
	return describeFindings(a.Findings, func(f CommandBlockFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func scbLoadText(a *CommandBlockAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func scbPropBool(props map[string]string, key string) (bool, bool) {
	return propsLookupBool(props, key)
}

func scbPropInt(props map[string]string, key string) (int, bool) {
	value, ok := props[strings.ToLower(key)]
	if !ok {
		return 0, false
	}
	return cfgParseInt(value)
}
