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
