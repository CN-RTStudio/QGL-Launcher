package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	ljMaxFindings      = 48
	ljMaxConfig        = 512 * 1024
	ljMaxJarName       = 128
	ljVulnVersion      = "2.17.0"
	ljReasonOK         = "ok"
	ljReasonMissing    = "missing"
	ljReasonVulnerable = "vulnerable-log4j"
	ljReasonJndiLookup = "jndi-lookup"
	ljReasonPattern    = "forced-lookup-pattern"
	ljReasonBadConfig  = "bad-config"
	ljReasonSymlink    = "symlink"
	ljReasonTooLarge   = "too-large"
	ljReasonBadName    = "bad-jar-name"
)

type Log4jFinding = auditFinding

type Log4jShellAudit struct {
	ServerDir string
	Jars      int
	Configs   int
	Findings  []Log4jFinding
}

func (a *Log4jShellAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, ljMaxFindings, Log4jFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *Log4jShellAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f Log4jFinding) bool { return f.Blocking })
}

func (a *Log4jShellAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f Log4jFinding) bool { return f.Reason != ljReasonOK && !f.Blocking })
}

func (a *Log4jShellAudit) Describe() string {
	return describeFindings(a.Findings, func(f Log4jFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func ljStripJarName(name string) (string, string) {
	base := strings.ToLower(filepath.Base(name))
	if !strings.HasSuffix(base, ".jar") {
		return "", ""
	}
	base = strings.TrimSuffix(base, ".jar")
	if !strings.HasPrefix(base, "log4j-core-") {
		return "", ""
	}
	version := strings.TrimPrefix(base, "log4j-core-")
	if version == "" {
		return "", ""
	}
	return base, version
}

func ljParseVersion(raw string) (int, int, int, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return 0, 0, 0, false
	}
	nums := make([]int, 0, 3)
	for i := 0; i < 3 && i < len(parts); i++ {
		chunk := parts[i]
		if i == 2 {
			idx := strings.IndexAny(chunk, "-+")
			if idx >= 0 {
				chunk = chunk[:idx]
			}
			if chunk == "" {
				chunk = "0"
			}
		}
		n, err := strconv.Atoi(chunk)
		if err != nil || n < 0 {
			return 0, 0, 0, false
		}
		nums = append(nums, n)
	}
	for len(nums) < 3 {
		nums = append(nums, 0)
	}
	return nums[0], nums[1], nums[2], true
}

func ljVersionVulnerable(major, minor int) bool {
	if major != 2 {
		return major == 1
	}
	return minor < 17
}
