package main

// assessQueueByteBudget 是聚合预算核心裁决。
//
//	existingSizes 队列中现有条目的声明大小（可含 <=0 未知项）
//	incoming       新条目声明大小
//
// 顺序：先验新条目自身（负 / 超大），再求现有之和（溢出），最后判聚合是否超上限。
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

// declaredSizesFromQueue 从下载队列里抽出声明大小切片，size<=0 的未知项保留为 0，
// 供 assessQueueByteBudget 求和（求和时会忽略 0）。单独成函数避免在入队热路径重复循环。
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
