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

func assessQueueByteBudget(existingSizes []int64, incoming int64) ByteBudgetDecision {
	d := ByteBudgetDecision{
		Incoming: incoming,
		Limit:    maxDownloadBudgetBytes,
	}
	inc, ok := normalizeDeclaredSize(incoming)
	if !ok {
		d.Reason = byteBudgetNegative
		return d
	}
	if inc > maxSingleDownloadDeclaredBytes {
		d.Reason = byteBudgetOversizeItem
		return d
	}
	existing, overflow := sumNonNegativeBytes(existingSizes)
	if overflow {
		d.Existing = maxDownloadBudgetBytes
		d.Reason = byteBudgetOverflow
		return d
	}
	d.Existing = existing
	projected, addOK := addChecked(existing, inc)
	if !addOK {
		d.Projected = maxDownloadBudgetBytes
		d.Reason = byteBudgetOverflow
		return d
	}
	d.Projected = projected
	if projected > maxDownloadBudgetBytes {
		d.Reason = byteBudgetOverBudget
		// Headroom 用“还差/超出多少”表达：这里为负，绝对值即超出量。
		d.Headroom = maxDownloadBudgetBytes - projected
		return d
	}
	d.OK = true
	d.Headroom = maxDownloadBudgetBytes - projected
	return d
}

func declaredSizesFromQueue(list []DownloadItem) []int64 {
	if len(list) == 0 {
		return nil
	}
	sizes := make([]int64, 0, len(list))
	for i := range list {
		s := list[i].SizeBytes
		if s < 0 {
			// 历史脏数据里若混入负值，按未知 0 处理而不是让整队预算直接判负。
			s = 0
		}
		sizes = append(sizes, s)
	}
	return sizes
}

// mapByteBudgetToQueueReason 把预算裁决原因映射成下载队列拒绝码（downloadqueue.go
// 的 dqReject* 体系），让入队闸能复用统一的 describeQueueReject 文案。
// 返回 dqRejectNone 表示预算放行。
func mapByteBudgetToQueueReason(r byteBudgetReason) string {
	switch r {
	case byteBudgetNegative:
		return dqRejectSizeNegative
	case byteBudgetOversizeItem:
		return dqRejectItemTooLarge
	case byteBudgetOverflow:
		return dqRejectBudgetOverflow
	case byteBudgetOverBudget:
		return dqRejectAggregateBudget
	default:
		return dqRejectNone
	}
}

// describeByteBudgetReject 直接给出预算拒绝原因的中文说明（供不经过队列文案的调用点）。
func describeByteBudgetReject(r byteBudgetReason) string {
	switch r {
	case byteBudgetNegative:
		return "下载大小声明为负数，已拒绝"
	case byteBudgetOversizeItem:
		return "单个下载任务声明大小超过 " + FormatBytes(maxSingleDownloadDeclaredBytes) + " 上限"
	case byteBudgetOverflow:
		return "下载队列聚合大小溢出，已拒绝"
	case byteBudgetOverBudget:
		return "下载队列聚合大小超过 " + FormatBytes(maxDownloadBudgetBytes) + " 上限，避免写满磁盘"
	default:
		return ""
	}
}
