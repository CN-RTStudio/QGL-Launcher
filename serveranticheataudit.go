package main

const (
	saxMaxFindings      = 40
	saxMaxYAML          = 512 * 1024
	saxMaxHiddenBlocks  = 64
	saxMaxRadius        = 4
	saxMinBlockHeight   = 16
	saxMaxBlockHeight   = 384
	saxReasonOK         = "ok"
	saxReasonMissing    = "missing"
	saxReasonSymlink    = "symlink"
	saxReasonTooLarge   = "too-large"
	saxReasonUnreadable = "unreadable"
	saxReasonDisabled   = "anti-xray-disabled"
	saxReasonModeWeak   = "engine-mode-weak"
	saxReasonModeBad    = "engine-mode-invalid"
	saxReasonHiddenNone = "hidden-blocks-empty"
	saxReasonHiddenMany = "hidden-blocks-too-many"
	saxReasonReplace    = "replacement-blocks-empty"
	saxReasonRadius     = "update-radius-out-of-range"
	saxReasonHeight     = "max-block-height-out-of-range"
	saxReasonLava       = "lava-obscuring-disabled"
	saxReasonListBad    = "list-entry-invalid"
)

type AntiXrayFinding = auditFinding
type AntiXrayAudit struct {
	ServerDir string
	Findings  []AntiXrayFinding
}

func (a *AntiXrayAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, saxMaxFindings, AntiXrayFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *AntiXrayAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f AntiXrayFinding) bool { return f.Blocking })
}
func (a *AntiXrayAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
func (a *AntiXrayAudit) Describe() string {
	return describeFileReason("反矿透配置未发现风险", a.Findings, 12)
}
func saxLoadText(a *AntiXrayAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}
