package main

import (
	"fmt"
	"strings"
)

func (a *App) enforceInstalledModsBeforeLaunch(versionID string) error {
	report, err := a.ScanInstalledMods(versionID)
	if err != nil {
		return err
	}
	if !report.Blocked {
		return nil
	}

	names := []string{}
	for _, r := range report.Risks {
		if r.Blocked {
			names = append(names, r.FileName)
		}
	}
	if len(names) > 8 {
		names = names[:8]
	}
	recordSecurityEvent(auditCategoryJarScan, auditSeverityCritical, auditActionBlocked,
		"mods-startup-scan",
		fmt.Sprintf("启动前 mods 安检命中 %d 个高危 jar，已阻止启动", len(names)))
	return fmt.Errorf("启动前安全扫描在 mods 目录发现高危 Mod（%d 个），已阻止启动；首个: %s。请移除或禁用后再试",
		countBlockedRisks(report), strings.Join(names, ", "))
}

func countBlockedRisks(r *ModDirScanReport) int {
	n := 0
	for _, risk := range r.Risks {
		if risk.Blocked {
			n++
		}
	}
	return n
}
