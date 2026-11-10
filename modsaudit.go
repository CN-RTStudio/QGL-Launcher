package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	modAuditMaxEntriesDefault = 4000             // 单目录条目数（含一层子目录）上界
	modAuditMaxEntryBytesDef  = int64(256) << 20 // 单文件流式哈希体积上界
	modAuditMaxTotalBytesDef  = int64(4) << 30   // 单目录审计总体积上界
	modAuditMaxSubdirs        = 32               // 一层子目录数量上界
	modAuditRelPathMaxLen     = 512              // 账本内相对路径长度上界
	modAuditBaselineVersion   = 1                // 账本格式版本
)

type ModAuditLimits struct {
	MaxEntries    int
	MaxEntryBytes int64
	MaxTotalBytes int64
}

func defaultModAuditLimits() ModAuditLimits {
	return ModAuditLimits{
		MaxEntries:    modAuditMaxEntriesDefault,
		MaxEntryBytes: modAuditMaxEntryBytesDef,
		MaxTotalBytes: modAuditMaxTotalBytesDef,
	}
}

type ModAuditEntry struct {
	RelPath string `json:"relPath"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	UMFS    string `json:"umfs"`
	ModTime string `json:"modTime,omitempty"`
}

const modAuditBaselineFile = "mods-audit-baseline.json"

// modAuditBaselinePath 返回基线账本路径（QGL 目录下，0600 私有文件）。
func (a *App) modAuditBaselinePath() string {
	return filepath.Join(a.GetQGLDir(), modAuditBaselineFile)
}

// auditModsRoots 解析本次要审计的 mods 根（与 moddirscan.resolveModsDirs 同口径：
// 隔离模式额外包含版本目录，全局目录始终包含）。返回绝对路径列表。
func (a *App) auditModsRoots(versionID string) []string {
	return a.resolveModsDirs(versionID)
}

// RebuildModsAuditBaseline 重新生成 mods 目录完整性基线账本，覆盖旧账本。
// 返回新账本的统计（目录数 / 文件总数 / 跳过数 / 是否触及上限）。生成账本本身
// 不判风险——它只是“此后的对账基准”。
func (a *App) RebuildModsAuditBaseline(versionID string) (*ModAuditBaselineInfo, error) {
	if versionID != "" && (strings.Contains(versionID, "..") ||
		strings.Contains(versionID, "/") || strings.Contains(versionID, "\\")) {
		return nil, modAuditError("版本ID包含非法字符")
	}
	roots := a.auditModsRoots(versionID)
	snap, skipped, limitHit, err := buildModAuditSnapshot(roots, defaultModAuditLimits())
	if err != nil {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityWarn, auditActionDetected,
			"mods-audit", "mods 审计基线生成失败")
		return nil, modAuditError("mods 审计基线生成失败")
	}
	if err := saveModAuditSnapshot(a.modAuditBaselinePath(), snap); err != nil {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityWarn, auditActionDetected,
			"mods-audit", "mods 审计基线落盘失败")
		return nil, modAuditError("mods 审计基线落盘失败")
	}
	info := &ModAuditBaselineInfo{
		Dirs:       len(snap.Dirs),
		TotalFiles: 0,
		Skipped:    skipped,
		LimitHit:   limitHit,
	}
	for _, d := range snap.Dirs {
		info.TotalFiles += len(d.Entries)
	}
	recordSecurityEvent(auditCategoryJarScan, auditSeverityInfo, auditActionDetected,
		"mods-audit", modAuditBaselineInfoText(info))
	return info, nil
}

func (a *App) AuditModsIntegrity(versionID string) (*ModAuditReport, error) {
	if versionID != "" && (strings.Contains(versionID, "..") ||
		strings.Contains(versionID, "/") || strings.Contains(versionID, "\\")) {
		return nil, modAuditError("版本ID包含非法字符")
	}
	baseline, err := loadModAuditSnapshot(a.modAuditBaselinePath())
	if err != nil {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityWarn, auditActionDetected,
			"mods-audit", "mods 审计基线读取失败")
		return nil, modAuditError("mods 审计基线读取失败")
	}
	roots := a.auditModsRoots(versionID)
	current, skipped, limitHit, err := buildModAuditSnapshot(roots, defaultModAuditLimits())
	if err != nil {
		return nil, modAuditError("mods 目录扫描失败")
	}
	report := auditModsAgainstBaseline(current, baseline)
	report.Skipped = skipped
	report.LimitHit = limitHit

	severity := auditSeverityInfo
	if report.HasRisks {
		severity = auditSeverityWarn
		if len(report.Tampered) > 0 {
			severity = auditSeverityCritical
		}
	}
	recordSecurityEvent(auditCategoryJarScan, severity, auditActionDetected,
		"mods-audit", modAuditSummaryText(report))
	return &report, nil
}

func (a *App) ClearModsAuditBaseline() error {
	path := a.modAuditBaselinePath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityWarn, auditActionDetected,
			"mods-audit", "mods 审计基线删除失败")
		return modAuditError("mods 审计基线删除失败")
	}
	recordSecurityEvent(auditCategoryJarScan, auditSeverityInfo, auditActionDetected,
		"mods-audit", "mods 审计基线已清除")
	return nil
}

// ModAuditBaselineInfo 是新基线账本的统计信息。
type ModAuditBaselineInfo struct {
	Dirs       int  `json:"dirs"`
	TotalFiles int  `json:"totalFiles"`
	Skipped    int  `json:"skipped"`
	LimitHit   bool `json:"limitHit"`
}

func modAuditBaselineInfoText(i *ModAuditBaselineInfo) string {
	return "mods 审计基线已建立: " +
		strconv.Itoa(i.Dirs) + " 个目录 / " +
		strconv.Itoa(i.TotalFiles) + " 个文件 / " +
		strconv.Itoa(i.Skipped) + " 个跳过"
}

// modAuditError 生成带统一前缀的错误文案，便于前端识别。
func modAuditError(msg string) error {
	return fmt.Errorf("mods 完整性审计: %s", msg)
}

type ModAuditDir struct {
	Dir     string          `json:"dir"` // 仅目录名（最后一段），不含绝对路径
	Entries []ModAuditEntry `json:"entries"`
}

// ModAuditSnapshot 是一次完整基线账本。
type ModAuditSnapshot struct {
	Version   int           `json:"version"`
	CreatedAt string        `json:"createdAt"`
	Dirs      []ModAuditDir `json:"dirs"`
}

// ModAuditDelta 描述对账时发现的一个差异条目。
type ModAuditDelta struct {
	Dir      string `json:"dir"`
	RelPath  string `json:"relPath"`
	Name     string `json:"name"`
	Kind     string `json:"kind"` // added / missing / tampered
	Baseline int64  `json:"baselineSize,omitempty"`
	Current  int64  `json:"currentSize,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// ModAuditReport 是一次对账的汇总，供前端安全页 / 手动体检消费。
type ModAuditReport struct {
	Total      int             `json:"total"`
	Added      []ModAuditDelta `json:"added"`
	Missing    []ModAuditDelta `json:"missing"`
	Tampered   []ModAuditDelta `json:"tampered"`
	Consistent int             `json:"consistent"`
	Skipped    int             `json:"skipped"` // 非普通文件 / 超限条目
	LimitHit   bool            `json:"limitHit"`
	HasRisks   bool            `json:"hasRisks"`
	Error      string          `json:"error,omitempty"`
}

func modAuditSafeRelPath(p string) bool {
	if p == "" || len(p) > modAuditRelPathMaxLen {
		return false
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
		return false
	}
	if strings.Contains(p, "\\") {
		return false
	}
	if hasControlCharStr(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
func hasControlCharStr(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x1F || s[i] == 0x7F {
			return true
		}
	}
	return false
}

func isValidUMFSHex(s string) bool {
	// UMFS hexdigest 只产出小写十六进制；不能用 hex.DecodeString（它会放行大写
	// A-F），否则同一内容可写入大小写两种哈希串，绕过账本的规范化去重。
	return IsLowerHex(s, 64)
}

// sanitizeModAuditEntry 逐字段净化账本条目；任何字段非法即整体丢弃（返回 false）。
func sanitizeModAuditEntry(raw *ModAuditEntry) bool {
	if raw == nil {
		return false
	}
	if !modAuditSafeRelPath(raw.RelPath) {
		return false
	}
	name := filepath.Base(strings.ReplaceAll(raw.RelPath, "/", string(filepath.Separator)))
	if name == "" || hasControlCharStr(name) || len(name) > 256 {
		return false
	}
	if raw.Size < 0 {
		return false
	}
	if !isValidUMFSHex(raw.UMFS) {
		return false
	}
	if raw.ModTime != "" && len(raw.ModTime) > 64 {
		return false
	}
	raw.Name = name
	return true
}
