package main

//
//

import ()

// ArchiveBomb 拒绝原因码。
const (
	BombReasonPolicy         = "bomb-policy-invalid"
	BombReasonTooManyEntries = "bomb-too-many-entries"
	BombReasonTotalTooLarge  = "bomb-total-uncompressed-too-large"
	BombReasonEntryTooLarge  = "bomb-single-entry-too-large"
	BombReasonRatio          = "bomb-compression-ratio-exceeded"
	BombReasonDuplicateName  = "bomb-duplicate-entry-name"
	BombReasonNameTooLong    = "bomb-entry-name-too-long"
	BombReasonNestedTooDeep  = "bomb-nested-depth-exceeded"
	BombReasonNegativeSize   = "bomb-negative-entry-size"
	BombReasonZip64Denied    = "bomb-zip64-not-allowed"
)

// ArchiveBombPolicy 限制解压时的资源预算。
type ArchiveBombPolicy struct {
	// MaxUncompressedTotal 全部条目解压后总字节上限。
	MaxUncompressedTotal int64
	// MaxSingleEntry 单个条目解压字节上限。
	MaxSingleEntry int64
	// MaxEntries 条目数量上限（含目录）。
	MaxEntries int
	// MaxCompressionRatio 允许的 解压/压缩 字节比；<=0 表示不校验。
	MaxCompressionRatio float64
	// MaxNameLen 条目名字节长度上限。
	MaxNameLen int
	// MaxNestDepth 允许的“压缩包内再出现压缩包”的递归层数。
	MaxNestDepth int
	// AllowZip64 是否允许 zip64 大尺寸条目。
	AllowZip64 bool
}

// DefaultArchiveBombPolicy 偏保守的默认预算：总 2GB、单条 512MB、5 万条、
// 比例 200:1、名字 1024 字节、嵌套 2 层。
func DefaultArchiveBombPolicy() ArchiveBombPolicy {
	return ArchiveBombPolicy{
		MaxUncompressedTotal: 2 << 30,
		MaxSingleEntry:       512 << 20,
		MaxEntries:           50_000,
		MaxCompressionRatio:  200,
		MaxNameLen:           1024,
		MaxNestDepth:         2,
		AllowZip64:           false,
	}
}

type bombErr struct{ code string }

func (e *bombErr) Error() string { return e.code }

// BombError 暴露断言入口，便于调用方区分“炸弹拒绝”和其它错误。
type BombError interface {
	error
	BombReason() string
}

func (e *bombErr) BombReason() string { return e.code }

func bombFail(code string) error { return &bombErr{code: code} }

// EntryInput 是调用方提供的一条压缩包条目客观信息。
type EntryInput struct {
	Name         string
	IsDir        bool
	Compressed   int64 // 该条目压缩后字节数；不可知时给 0
	Uncompressed int64 // 该条目声称/实得的解压字节数
	Zip64        bool  // 该条目是否使用 zip64 扩展尺寸
}

// ArchiveBombAuditor 是单次解压过程的有状态审计器。
type ArchiveBombAuditor struct {
	policy       ArchiveBombPolicy
	entries      int
	totalUncomp  int64
	totalComp    int64
	seenNames    map[string]struct{}
	largestRatio float64
}

// NewArchiveBombAuditor 按策略构造审计器；策略非法直接报错，防止“零值全放开”。
func NewArchiveBombAuditor(policy ArchiveBombPolicy) (*ArchiveBombAuditor, error) {
	if policy.MaxUncompressedTotal <= 0 || policy.MaxSingleEntry <= 0 ||
		policy.MaxEntries <= 0 || policy.MaxNameLen <= 0 || policy.MaxNestDepth < 0 {
		return nil, bombFail(BombReasonPolicy)
	}
	return &ArchiveBombAuditor{
		policy:    policy,
		seenNames: make(map[string]struct{}),
	}, nil
}

// AddEntry 在解压某个条目前调用。返回的错误实现 BombError，可断言原因码。
