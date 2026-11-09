package main

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
