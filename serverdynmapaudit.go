package main

const (
	spdMaxFindings       = 36
	spdMaxConfig         = 256 * 1024
	spdMaxProps          = 256 * 1024
	spdPrivilegedPortMax = 1024
	spdReasonOK          = "ok"
	spdReasonMissing     = "missing"
	spdReasonSymlink     = "symlink"
	spdReasonTooLarge    = "too-large"
	spdReasonUnreadable  = "unreadable"
	spdReasonPort        = "webserver-port-invalid"
	spdReasonPortPriv    = "webserver-port-privileged"
	spdReasonPortClash   = "webserver-port-conflict"
	spdReasonBindAll     = "webserver-bind-all"
	spdReasonSymlinks    = "webserver-allow-symlinks"
	spdReasonCORS        = "cors-wildcard"
	spdReasonCDN         = "cdn-insecure"
	spdReasonTilePath    = "tilespath-invalid"
	spdReasonBadValue    = "bad-value"
)

type DynmapFinding = auditFinding

type DynmapAudit struct {
	ServerDir string
	Findings  []DynmapFinding
}

func (a *DynmapAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spdMaxFindings, DynmapFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *DynmapAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f DynmapFinding) bool { return f.Blocking })
}

func (a *DynmapAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *DynmapAudit) Describe() string {
	return describeFileReason("网页地图配置未发现风险", a.Findings, 12)
}

func spdLoadText(a *DynmapAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func spdBool(props map[string]string, key string) (bool, bool) {
	return propsLookupBool(props, key)
}

func spdPortConflict(serverPort, webPort int) bool {
	return serverPort > 0 && serverPort == webPort
}
