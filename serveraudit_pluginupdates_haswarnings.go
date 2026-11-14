package main

import (
	"fmt"
)

func (a *PluginUpdateAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginUpdateFinding) bool {
		return f.Reason != spuReasonOK && f.Reason != spuReasonScanNote && !f.Blocking
	})
}

func (a *PluginUpdateAudit) Describe() string {
	return describeFindings(a.Findings, func(f PluginUpdateFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func spuAutoUpdateKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"auto-update", "auto_update", "update-check", "update_check",
		"check-for-updates", "check_for_updates", "update-on-start",
	})
}
