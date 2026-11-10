package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// modsScanMaxJars 限制单次启动前最多扫描的 jar 数量。
	modsScanMaxJars = 2000
)

type ModJarRisk struct {
	Path         string   `json:"path"`
	FileName     string   `json:"fileName"`
	Blocked      bool     `json:"blocked"`
	JarCritical  int      `json:"jarCritical"`
	Log4Critical int      `json:"log4Critical"`
	Warnings     int      `json:"warnings"`
	Reasons      []string `json:"reasons"`
	ScanError    string   `json:"scanError,omitempty"`
}
type ModDirScanReport struct {
	ScannedDirs  []string     `json:"scannedDirs"`
	ScannedJars  int          `json:"scannedJars"`
	Skipped      int          `json:"skipped"`
	Risks        []ModJarRisk `json:"risks"`
	Blocked      bool         `json:"blocked"`
	LimitReached bool         `json:"limitReached"`
}

func (a *App) resolveModsDirs(versionID string) []string {
	mcDir := a.GetMinecraftDir()
	seen := map[string]bool{}
	dirs := []string{}

	add := func(d string) {
		if d == "" {
			return
		}
		if abs, err := filepath.Abs(d); err == nil {
			d = abs
		}
		if !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}

	add(filepath.Join(mcDir, "mods"))
	if a.isVersionIsolated() && versionID != "" {
		add(filepath.Join(mcDir, "versions", versionID, "mods"))
	}
	return dirs
}

func listEnabledJars(dir string) ([]string, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, err
	}

	jars := []string{}
	skipped := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".jar") {
			// 非 jar（.jar.disabled 因后缀不是 .jar 也在此被排除）不参与加载，跳过。
			continue
		}
		if len(jars) >= modsScanMaxJars {
			skipped++
			continue
		}
		jars = append(jars, filepath.Join(dir, name))
	}
	sort.Strings(jars)
	return jars, skipped, nil
}

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
