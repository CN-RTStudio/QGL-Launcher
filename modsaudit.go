package main

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
