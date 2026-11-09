package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

func scanOneInstalledJar(jarPath string) ModJarRisk {
	risk := ModJarRisk{
		Path:     jarPath,
		FileName: filepath.Base(jarPath),
		Reasons:  []string{},
	}

	jarRep, jarErr := enforceModJarScan(jarPath, "mods-startup-scan", risk.FileName)
	if jarErr != nil {
		risk.Blocked = true
		risk.ScanError = jarErr.Error()
		risk.Reasons = append(risk.Reasons, "通用扫描阻断: "+jarErr.Error())
	}
	if jarRep != nil {
		for _, f := range jarRep.Findings {
			switch f.Severity {
			case JarSeverityCritical:
				risk.JarCritical++
				risk.Blocked = true
				risk.Reasons = append(risk.Reasons, "["+f.Rule+"] "+f.Entry)
			case JarSeverityWarn:
				risk.Warnings++
			}
		}
	}

	logRep, logErr := enforceLog4ShellScan(jarPath, "mods-startup-scan", risk.FileName)
	if logErr != nil {
		risk.Blocked = true
		if risk.ScanError == "" {
			risk.ScanError = logErr.Error()
		}
		risk.Reasons = append(risk.Reasons, "Log4Shell 扫描阻断: "+logErr.Error())
	}
	if logRep != nil {
		for _, f := range logRep.Findings {
			switch f.Severity {
			case JarSeverityCritical:
				risk.Log4Critical++
				risk.Blocked = true
				risk.Reasons = append(risk.Reasons, "["+f.Rule+"] "+f.Entry)
			case JarSeverityWarn:
				risk.Warnings++
			}
		}
	}

	return risk
}

// ScanInstalledMods 扫描指定版本关联的 mods 目录（供前端安全页 / 手动体检调用）。
// 只读：绝不删除或隔离文件，只把结论返回给 UI，由用户决定如何处理。
func (a *App) ScanInstalledMods(versionID string) (*ModDirScanReport, error) {
	if versionID != "" {
		if strings.Contains(versionID, "..") || strings.Contains(versionID, "/") ||
			strings.Contains(versionID, "\\") {
			return nil, fmt.Errorf("版本ID包含非法字符")
		}
	}

	report := &ModDirScanReport{Risks: []ModJarRisk{}}
	for _, dir := range a.resolveModsDirs(versionID) {
		jars, skipped, err := listEnabledJars(dir)
		if err != nil {
			recordSecurityEvent(auditCategoryJarScan, auditSeverityWarn, auditActionDetected,
				"mods-startup-scan", "读取 mods 目录失败: "+sanitizeLogLine(dir))
			continue
		}
		report.ScannedDirs = append(report.ScannedDirs, dir)
		report.Skipped += skipped
		if len(jars) >= modsScanMaxJars {
			report.LimitReached = true
		}

		for _, jar := range jars {
			report.ScannedJars++
			risk := scanOneInstalledJar(jar)
			if risk.Blocked || risk.Warnings > 0 {
				report.Risks = append(report.Risks, risk)
			}
			if risk.Blocked {
				report.Blocked = true
			}
		}
	}
	return report, nil
}

// enforceInstalledModsBeforeLaunch 在 JVM 启动前对 mods 目录做强制安检：
// 存在任一 critical 命中的 jar 时返回错误，阻止本次启动。
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
