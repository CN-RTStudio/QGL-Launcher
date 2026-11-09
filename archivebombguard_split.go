package main

//
//

import (
	"fmt"
)

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
