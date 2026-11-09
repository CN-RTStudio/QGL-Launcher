package main

import "fmt"

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
