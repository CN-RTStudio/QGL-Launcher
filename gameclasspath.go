package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// gameclasspath.go —— 游戏主启动 classpath 与本地库/natives 路径的“最终归属审计”。
//
// 威胁模型：
//   游戏 JVM 的 -cp / -Djava.library.path 决定了类与本地库（.dll/.so/.dylib）的搜索
//   顺序。它们由版本 JSON（Mojang / Forge / Fabric / 第三方整合包，都是外部数据）经
//   多条路径拼出：buildClasspath 里的 mavenNameToPath、isSafeRelPath、Jar/InheritsFrom
//   拼 versions/<name>/<name>.jar，natives 目录等。这些环节各自有校验，但“整条
//   classpath 最终是否全部落在 .minecraft 之内、是否有重复/越界/非 jar 条目”缺少一道
//   独立的、不依赖任何单一上游 helper 正确性的总验收。
//
//   攻击面：
//     1) 某个上游拼路径函数被绕过/回归，引入 libraries 之外的绝对或穿越 jar，JVM 会
//        优先加载攻击者放置的类（RCE）；
//     2) classpath 塞入 UNC / 含控制字符的条目；
//     3) 条目数无界（畸形整合包塞进几万条）拖慢/撑爆命令行；
//     4) 大量重复条目改变类解析顺序，用于遮蔽正版类。
//
//   本模块与 launchtarget.auditClasspath 的区别：游戏 classpath 条目是“绝对路径”，
//   且允许的根是整个 .minecraft（libraries 与 versions 都在其下），还需要去重统计与
//   数量上限；因此单独实现，判定保持纯字符串/路径归一化，不触碰文件系统。

const (
	// 上限取“远大于任何真实整合包、又能拦住畸形灌入”的值：现代大型整合包 classpath
	// 一般数百条，给到数千仍安全；不设会误伤正常模组的小上限。
	maxGameClasspathEntries = 16384
	// natives/library 路径总长上限，与系统 MAX_PATH 级别对齐。
	maxGameLocalPathLen = 4096
)

// GameClasspathAudit 聚合 classpath 最终归属审计结论。
type GameClasspathAudit struct {
	Findings    []LaunchFinding `json:"findings"`
	Critical    int             `json:"critical"`
	Warns       int             `json:"warns"`
	SafeEntries []string        `json:"safeEntries"` // 通过全部强制检查的条目（保持原顺序、去重）
	Rejected    int             `json:"rejected"`
}

func (g *GameClasspathAudit) add(code, severity, field, detail string) {
	g.Findings = append(g.Findings, LaunchFinding{Code: code, Severity: severity, Field: field, Detail: detail})
	switch severity {
	case launchSeverityCritical:
		g.Critical++
	case launchSeverityWarn:
		g.Warns++
	}
}

// HasCritical 报告是否存在必须阻断启动的结论。
func (g *GameClasspathAudit) HasCritical() bool { return g.Critical > 0 }

// FirstCriticalCode 返回首个 critical 代码。
func (g *GameClasspathAudit) FirstCriticalCode() string {
	for _, f := range g.Findings {
		if f.Severity == launchSeverityCritical {
			return f.Code
		}
	}
	return ""
}

// classifyGameClasspathEntry 判定单条 classpath 条目的安全性。返回 "" 表示安全，否则
// 返回稳定错误 code。roots 为允许的根集合（通常是 .minecraft）。
func classifyGameClasspathEntry(entry string, roots []string) string {
	if entry == "" {
		return "gcp-empty"
	}
	if len(entry) > maxPathLen {
		return "gcp-long"
	}
	if containsControlByte(entry) {
		return "gcp-control"
	}
	if isUNC(entry) {
		return "gcp-unc"
	}
	if !filepath.IsAbs(entry) {
		return "gcp-not-absolute"
	}
	if hasTraversalSegment(entry) {
		return "gcp-traversal"
	}
	if !strings.EqualFold(filepath.Ext(entry), ".jar") {
		return "gcp-not-jar"
	}
	if !containedInAnyRoot(entry, roots) {
		return "gcp-outside-root"
	}
	return ""
}

// AuditGameClasspath 对游戏主 classpath 做最终验收：数量有界、逐条强制校验（绝对 .jar、
// 无 UNC/穿越/控制符、必须落在 roots 内），并去重。任一“危险条目”出现都记 critical；
// SafeEntries 只保留安全且去重后的条目，调用方可据此重建干净 classpath。
func AuditGameClasspath(entries []string, roots []string) *GameClasspathAudit {
	g := &GameClasspathAudit{}
	if len(entries) > maxGameClasspathEntries {
		g.add("gcp-too-many", launchSeverityCritical, "classpath",
			fmt.Sprintf("classpath 条目数 %d 超过上限 %d", len(entries), maxGameClasspathEntries))
	}
	seen := make(map[string]struct{}, len(entries))
	dupCount := 0
	for i, entry := range entries {
		field := fmt.Sprintf("classpath[%d]", i)
		if code := classifyGameClasspathEntry(entry, roots); code != "" {
			g.add(code, launchSeverityCritical, field, "不安全的 classpath 条目: "+code)
			g.Rejected++
			continue
		}
		key := strings.ToLower(filepath.Clean(entry))
		if _, ok := seen[key]; ok {
			dupCount++
			continue // 重复条目不再次加入，但也不算危险（仅统计去重）
		}
		seen[key] = struct{}{}
		g.SafeEntries = append(g.SafeEntries, entry)
	}
	if dupCount > 0 {
		g.add("gcp-duplicate", launchSeverityWarn, "classpath",
			fmt.Sprintf("classpath 含 %d 条重复条目（已去重）", dupCount))
	}
	if len(g.SafeEntries) == 0 {
		g.add("gcp-all-rejected", launchSeverityCritical, "classpath", "没有任何安全可用的 classpath 条目")
	}
	return g
}

// AuditGameLocalPaths 审计游戏本地路径：natives 目录（java.library.path /
// lwjgl.librarypath）与 libraries 目录必须绝对、有界、无 UNC/穿越/控制符，且落在
// 允许根（.minecraft）内。防止被篡改进程把本地库搜索目录指到外部攻击者目录。
func AuditGameLocalPaths(nativesDir, librariesDir, assetsDir string, roots []string) *LaunchAudit {
	a := &LaunchAudit{}
	check := func(label, p string) {
		if strings.TrimSpace(p) == "" {
			a.add("localpath-empty", launchSeverityCritical, label, "本地路径为空")
			return
		}
		if len(p) > maxGameLocalPathLen {
			a.add("localpath-long", launchSeverityCritical, label, "本地路径过长")
		}
		if containsControlByte(p) {
			a.add("localpath-control", launchSeverityCritical, label, "本地路径含控制字符")
		}
		if isUNC(p) {
			a.add("localpath-unc", launchSeverityCritical, label, "不允许把网络共享作为本地路径")
		}
		if !filepath.IsAbs(p) {
			a.add("localpath-not-absolute", launchSeverityCritical, label, "本地路径必须是绝对路径")
		}
		if hasTraversalSegment(p) {
			a.add("localpath-traversal", launchSeverityCritical, label, "本地路径含目录穿越段")
		}
		if !containedInAnyRoot(p, roots) {
			a.add("localpath-outside", launchSeverityCritical, label, "本地路径逃逸出游戏目录")
		}
	}
	check("nativesDir", nativesDir)
	check("librariesDir", librariesDir)
	if strings.TrimSpace(assetsDir) != "" {
		check("assetsDir", assetsDir)
	}
	a.tally()
	return a
}
