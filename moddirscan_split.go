package main

import (
	"path/filepath"
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
