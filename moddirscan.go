package main

// moddirscan.go —— 启动前 / 手动对“已经在 mods 目录里”的 jar 做存量安全扫描。
//
// 此前的 enforceModJarScan 只覆盖“本程序经手”的两条路径：在线下载落盘、用户点
// 导入复制。但用户完全可能：
//   - 用别的启动器 / 手动把 jar 拖进 mods 目录；
//   - 从压缩包解压、从网盘拷贝一批 Mod；
//   - 降级覆盖、被别的进程写入恶意 jar。
//
// 这些文件从来没经过本程序的哈希白名单与静态扫描，却会在下次启动时被 Mod
// 加载器直接加载。因此在真正拉起 JVM 之前，需要把 mods 目录里所有启用的
// jar 过一遍 jarscan（通用恶意形态）+ log4shell（Log4Shell/JNDI 专项）。
//
// 设计要点：
//   - 只读、不执行、不解压落地；
//   - 扫描数量有界，避免恶意目录塞上万条目拖垮启动；
//   - .jar.disabled 等已禁用条目不参与启动加载，跳过；
//   - 任一 critical 即阻止本次启动并给出命中文件，其余文件继续扫完以便一次性
//     报告全部问题（而不是修一个再扫一个）。

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

// ModJarRisk 描述单个存量 jar 的扫描结论。
type ModJarRisk struct {
	Path        string `json:"path"`
	FileName    string `json:"fileName"`
	Blocked     bool   `json:"blocked"`
	JarCritical int    `json:"jarCritical"`
	Log4Critical int   `json:"log4Critical"`
	Warnings    int    `json:"warnings"`
	Reasons     []string `json:"reasons"`
	ScanError   string `json:"scanError,omitempty"`
}

// ModDirScanReport 是一次 mods 目录存量扫描的汇总。
type ModDirScanReport struct {
	ScannedDirs []string       `json:"scannedDirs"`
	ScannedJars int            `json:"scannedJars"`
	Skipped     int            `json:"skipped"`
	Risks       []ModJarRisk   `json:"risks"`
	Blocked     bool           `json:"blocked"`
	LimitReached bool          `json:"limitReached"`
}

// resolveModsDirs 返回本次需要扫描的 mods 目录（去重、绝对路径）。
// 隔离模式下版本目录是真正生效的位置；全局目录仍可能被旧实例 / 共享实例加载，
// 一并扫描；非隔离模式只扫全局目录。
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

// listEnabledJars 列出目录下“会被加载”的 jar（.jar），已禁用的 .jar.disabled
// 跳过；返回按文件名排序的结果，保证扫描与报告稳定可复现。
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

// scanOneInstalledJar 对单个存量 jar 跑两套扫描并汇总风险；不做删除。
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
