package main

const (
	// maxSingleDownloadDeclaredBytes 单条任务声明大小上限（512GiB），
	// 与下载哈希可处理上限 MAX_HASHABLE_DOWNLOAD_BYTES 同量级，拦“单条天文数字”。
	maxSingleDownloadDeclaredBytes int64 = 512 << 30
	// maxDownloadBudgetBytes 整个下载队列“已知大小”的聚合上限（1TiB）。
	// 只有聚合声称要写超过 1TiB 才拒绝，正常批量下载远到不了这里。
	maxDownloadBudgetBytes int64 = 1 << 40
)

// 字节预算拒绝原因码。
type byteBudgetReason string

const (
	byteBudgetOK           byteBudgetReason = ""
	byteBudgetNegative     byteBudgetReason = "negative-size"             // 声明了负大小
	byteBudgetOversizeItem byteBudgetReason = "item-too-large"            // 单条超过 512GiB
	byteBudgetOverflow     byteBudgetReason = "size-overflow"             // 聚合求和溢出 int64
	byteBudgetOverBudget   byteBudgetReason = "aggregate-budget-exceeded" // 聚合超过 1TiB
)

// ByteBudgetDecision 是一次聚合预算裁决。
type ByteBudgetDecision struct {
	OK        bool
	Reason    byteBudgetReason
	Existing  int64 // 队列中已知大小之和（size<=0 的未知项按 0）
	Incoming  int64 // 新条目声明大小（<=0 视为未知 0）
	Projected int64 // Existing+Incoming（OK / over-budget 时有效）
	Limit     int64 // 聚合上限
	Headroom  int64 // 距上限还剩多少（over-budget 时为负，表示超出量）
}

// normalizeDeclaredSize 把新条目的声明大小归一化：负数是非法（不是“未知”），
// 0 / 正数原样；未知只能用 0 表达，不允许用负值。
func normalizeDeclaredSize(size int64) (int64, bool) {
	if size < 0 {
		return 0, false
	}
	return size, true
}
