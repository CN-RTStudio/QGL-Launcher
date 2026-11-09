package main

import (
	"strings"
)

const (
	sbmMaxFindings     = 36
	sbmMaxConfig       = 256 * 1024
	sbmMaxProps        = 256 * 1024
	sbmPrivilegedPort  = 1024
	sbmReasonOK        = "ok"
	sbmReasonMissing   = "missing"
	sbmReasonSymlink   = "symlink"
	sbmReasonTooLarge  = "too-large"
	sbmReasonUnread    = "unreadable"
	sbmReasonPort      = "webserver-port-invalid"
	sbmReasonPrivPort  = "webserver-port-privileged"
	sbmReasonPortClash = "webserver-port-conflict"
	sbmReasonBindAll   = "webserver-bind-all"
	sbmReasonDownload  = "accept-download-enabled"
	sbmReasonDataPath  = "data-path-escape"
	sbmReasonMetrics   = "metrics-enabled"
	sbmReasonRate      = "rate-limit-disabled"
	sbmReasonBadValue  = "bad-value"
)

type BlueMapFinding = auditFinding

type BlueMapAudit struct {
	ServerDir string
	Findings  []BlueMapFinding
}

func (a *BlueMapAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sbmMaxFindings, BlueMapFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *BlueMapAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BlueMapFinding) bool { return f.Blocking })
}

func (a *BlueMapAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *BlueMapAudit) Describe() string {
	return describeFileReason("BlueMap 网页地图配置未发现风险", a.Findings, 12)
}

func sbmLoadText(a *BlueMapAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func sbmParseConf(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if trimmed == "{" || trimmed == "}" || strings.HasSuffix(trimmed, "{") {
			continue
		}
		sep := strings.IndexAny(trimmed, ":=")
		if sep <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:sep]))
		if dot := strings.LastIndex(key, "."); dot >= 0 {
			key = key[dot+1:]
		}
		if space := strings.LastIndex(key, " "); space >= 0 {
			key = key[space+1:]
		}
		value := strings.TrimSpace(trimmed[sep+1:])
		value = strings.TrimSuffix(value, ",")
		value = cfgStripQuotes(value)
		out[key] = value
	}
	return out
}

func sbmBool(props map[string]string, key string) (bool, bool) {
	return propsLookupBool(props, key)
}
