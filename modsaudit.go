package main

// modsaudit.go —— mods 目录完整性审计内核。
//
// 背景：
//   启动器经手的 jar（在线下载、导入复制）都有静态扫描与哈希白名单保护；但用户完全
//   可能用手拖 / 压缩包解压 / 别的启动器往 mods 目录塞文件，这类“没经过哈希与扫描
//   通道”的文件在下次启动时仍会被 Mod 加载器加载。此前只有存量静态扫描
//   （moddirscan / jarscan / log4shell），缺一道“目录级完整性账本”：把 mods 目录里
//   所有普通文件的位置 / 体积 / 哈希记成基线，之后随时可对账，检出新增、缺失与被
//   篡改的文件，并按风险分级提示。
//
// 设计要点：
//   - 只读、不执行、不解压；对每个文件流式算 UMFS（本地用途哈希，遵守“本地哈希用
//     UMFS”约定），绝不同时把整个文件读进内存；
//   - 扫描有界：条目数 / 单文件体积 / 总体积三道上限，防“恶意塞满目录 -> 审计把
//     启动拖死 / 把磁盘读爆”的本地 DoS；
//   - 非普通文件（符号链接 / 设备 / 管道）一律跳过并计数，防审计被链接指向的敏感
//     外部文件带偏；目录递归只走一层子目录（mods 常见布局是“文件平铺 + 少量子
//     目录”），子目录内条目同样受总数上界约束；
//   - 基线落盘走 writePrivateJSONBounded（0600 原子写），读取走 readLocalJSONBounded
//     有界读 + 逐字段净化：相对路径必须安全（拒绝绝对路径 / ".." / 控制字符 / 超
//     长），哈希必须是 64 位十六进制，任何脏条目整体丢弃，绝不半信任恢复；
//   - 对账结果分四类：新增（基线没有 -> 未经验证来源，风险提示）、缺失（基线有但
//     已不在 -> 可能是用户删了，也可能是被整目录替换）、篡改（同名且体积变化或
//     哈希不一致 -> 最高风险，可能被恶意改写）、一致。分类结果只做上报与审计事件，
//     不自动删文件——删 mods 由用户决定。

import (
	"path/filepath"
	"strings"
)

// mods 审计的资源上界。
const (
	modAuditMaxEntriesDefault = 4000             // 单目录条目数（含一层子目录）上界
	modAuditMaxEntryBytesDef  = int64(256) << 20 // 单文件流式哈希体积上界
	modAuditMaxTotalBytesDef  = int64(4) << 30   // 单目录审计总体积上界
	modAuditMaxSubdirs        = 32               // 一层子目录数量上界
	modAuditRelPathMaxLen     = 512              // 账本内相对路径长度上界
	modAuditBaselineVersion   = 1                // 账本格式版本
)

// ModAuditLimits 是一次 mods 审计允许消耗的资源上限。
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

// ModAuditEntry 是账本里一个文件的记录。RelPath 相对 mods 根，使用正斜杠分隔，
// 保证跨平台可移植。
type ModAuditEntry struct {
	RelPath string `json:"relPath"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	UMFS    string `json:"umfs"`
	ModTime string `json:"modTime,omitempty"`
}

// ModAuditDir 是某个 mods 目录在账本里的快照。
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

// ---- 安全净化 ----

// modAuditSafeRelPath 判断账本里的相对路径是否可接受：非空、不超长、不含控制字符、
// 不是绝对路径、不含 ".." 段、不用反斜杠（账本统一正斜杠）。
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

// hasControlCharStr 判断字符串是否含 ASCII 控制字符（与 nameguard 口径一致）。
func hasControlCharStr(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x1F || s[i] == 0x7F {
			return true
		}
	}
	return false
}

// isValidUMFSHex 判断账本里的哈希是否 64 位小写十六进制（UMFS 输出 32 字节）。
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

// ---- 目录扫描 ----

// listModAuditFiles 平铺列出 mods 目录下（含一层子目录）的普通文件相对路径，跳过
// 符号链接 / 设备 / 管道等特殊条目，并受条目数与子目录数上界约束。返回相对路径
// 列表（正斜杠）、跳过计数、是否触及上限。
