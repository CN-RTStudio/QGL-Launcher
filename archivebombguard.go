package main

// archivebombguard.go —— 压缩包“解压炸弹 / 资源耗尽”审计内核。
//
// zipextract.go 解决的是“条目路径写到哪里”（Zip Slip / 符号链接），本模块解决
// 的是“条目内容能膨胀到多大”：
//   1. 高压缩比炸弹：几 KB 的压缩数据声称解压出几十 GB（gz/zip ratio bomb）；
//   2. 总量炸弹：上万个小条目累计撑爆磁盘 / inode；
//   3. 单文件巨型条目：单条就超过可用预算；
//   4. 重复条目名：同一名字出现多次，制造“后写覆盖先写”的混淆与 TOCTOU；
//   5. 嵌套压缩包递归：解压出的压缩包再解压，层数失控放大；
//   6. zip64 超大尺寸字段：未经 zip64 策略允许的 0xFFFFFFFF 标记/8 字节长度。
//
// 设计为“流式累加审计”：调用方每读到一个条目（含压缩/未压缩字节数）就调用
// AddEntry，内核即时给出拒绝，避免先全部解压到磁盘再判断。纯决策，不碰文件。

import (
	"fmt"
)

// ArchiveBomb 拒绝原因码。
const (
	BombReasonPolicy        = "bomb-policy-invalid"
	BombReasonTooManyEntries = "bomb-too-many-entries"
	BombReasonTotalTooLarge = "bomb-total-uncompressed-too-large"
	BombReasonEntryTooLarge = "bomb-single-entry-too-large"
	BombReasonRatio         = "bomb-compression-ratio-exceeded"
	BombReasonDuplicateName = "bomb-duplicate-entry-name"
	BombReasonNameTooLong   = "bomb-entry-name-too-long"
	BombReasonNestedTooDeep = "bomb-nested-depth-exceeded"
	BombReasonNegativeSize  = "bomb-negative-entry-size"
	BombReasonZip64Denied   = "bomb-zip64-not-allowed"
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
func (a *ArchiveBombAuditor) AddEntry(in EntryInput) error {
	if in.Compressed < 0 || in.Uncompressed < 0 {
		return bombFail(BombReasonNegativeSize)
	}
	if len(in.Name) > a.policy.MaxNameLen {
		return bombFail(BombReasonNameTooLong)
	}
	if a.entries >= a.policy.MaxEntries {
		return bombFail(BombReasonTooManyEntries)
	}
	if in.Zip64 && !a.policy.AllowZip64 {
		return bombFail(BombReasonZip64Denied)
	}
	// 重复名字（区分大小写按归档原样比较）：可能用于覆盖混淆。
	if _, dup := a.seenNames[in.Name]; dup {
		return bombFail(BombReasonDuplicateName)
	}
	if in.Uncompressed > a.policy.MaxSingleEntry {
		return bombFail(BombReasonEntryTooLarge)
	}
	if a.totalUncomp+in.Uncompressed > a.policy.MaxUncompressedTotal {
		return bombFail(BombReasonTotalTooLarge)
	}

	// 压缩比按“当前累计 + 本条目”滚动计算，避免单条小压缩大解压钻空子。
	// 目录条目不参与比值（压缩字节常记 0）。
	if !in.IsDir && a.policy.MaxCompressionRatio > 0 {
		comp := a.totalComp + in.Compressed
		uncomp := a.totalUncomp + in.Uncompressed
		if comp > 0 {
			r := float64(uncomp) / float64(comp)
			if r > a.largestRatio {
				a.largestRatio = r
			}
			if r > a.policy.MaxCompressionRatio {
				return bombFail(BombReasonRatio)
			}
		}
	}

	a.seenNames[in.Name] = struct{}{}
	a.entries++
	a.totalUncomp += in.Uncompressed
	a.totalComp += in.Compressed
	return nil
}

// AssertNestDepth 校验嵌套压缩包递归层数（最外层为 0）。
func (p ArchiveBombPolicy) AssertNestDepth(depth int) error {
	if depth < 0 {
		return bombFail(BombReasonNestedTooDeep)
	}
	if depth > p.MaxNestDepth {
		return bombFail(BombReasonNestedTooDeep)
	}
	return nil
}

// Snapshot 返回当前累计计量（只读用途，供进度/日志）。
func (a *ArchiveBombAuditor) Snapshot() (entries int, totalUncompressed int64, totalCompressed int64, peakRatio float64) {
	return a.entries, a.totalUncomp, a.totalComp, a.largestRatio
}

// IsBombError 便于调用方不做类型断言即可判断。
func IsBombError(err error) bool {
	if err == nil {
		return false
	}
	if be, ok := err.(BombError); ok {
		_ = be
		return true
	}
	return false
}

// DescribeBombReason 把原因码翻译成排障可读文本。
func DescribeBombReason(code string) string {
	switch code {
	case BombReasonPolicy:
		return "解压预算策略非法（存在 <=0 的上限），拒绝解压"
	case BombReasonTooManyEntries:
		return "压缩包条目数量超过上限"
	case BombReasonTotalTooLarge:
		return "全部条目解压后总大小超过预算"
	case BombReasonEntryTooLarge:
		return "单个条目解压大小超过预算"
	case BombReasonRatio:
		return "压缩比异常（疑似解压炸弹）"
	case BombReasonDuplicateName:
		return "压缩包内出现重复条目名"
	case BombReasonNameTooLong:
		return "条目名过长"
	case BombReasonNestedTooDeep:
		return "嵌套压缩包层数超过上限"
	case BombReasonNegativeSize:
		return "条目尺寸为负（尺寸字段被篡改）"
	case BombReasonZip64Denied:
		return "未显式允许 zip64 却出现超大尺寸条目"
	default:
		return fmt.Sprintf("未知解压炸弹原因码: %s", code)
	}
}
