package main

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
