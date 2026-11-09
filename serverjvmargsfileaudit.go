package main

import (
	"strconv"
	"strings"
)

const (
	sjaMaxFindings  = 28
	sjaMaxFile      = 64 * 1024
	sjaMaxHeapGB    = 32
	sjaReasonMiss   = "missing"
	sjaReasonLink   = "symlink"
	sjaReasonLarge  = "too-large"
	sjaReasonRead   = "unreadable"
	sjaReasonAgent  = "java-agent"
	sjaReasonBoot   = "bootclasspath"
	sjaReasonExec   = "on-error-command"
	sjaReasonArg    = "argfile-indirection"
	sjaReasonHeap   = "heap-too-large"
	sjaReasonPolicy = "security-manager"
	sjaReasonQuote  = "unbalanced-quote"
	sjaReasonCTRL   = "control-characters"
	sjaReasonJMX    = "jmx-exposed"
)

type JvmArgsFinding = auditFinding

type JvmArgsAudit struct {
	ServerDir string
	Findings  []JvmArgsFinding
}

func (a *JvmArgsAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sjaMaxFindings, JvmArgsFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *JvmArgsAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JvmArgsFinding) bool { return f.Blocking })
}

func (a *JvmArgsAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *JvmArgsAudit) Describe() string {
	return describeReasonDetail("user_jvm_args.txt 未发现风险", a.Findings, 12)
}

func sjaHeapGB(value string) (float64, bool) {
	upper := strings.ToUpper(strings.TrimSpace(value))
	mul := float64(1)
	switch {
	case strings.HasSuffix(upper, "G"):
		mul = 1
	case strings.HasSuffix(upper, "M"):
		mul = 1.0 / 1024.0
	case strings.HasSuffix(upper, "K"):
		mul = 1.0 / (1024.0 * 1024.0)
	default:
		return 0, false
	}
	number := strings.TrimSpace(upper[:len(upper)-1])
	v, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0, false
	}
	return v * mul, true
}
