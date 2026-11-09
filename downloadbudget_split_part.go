package main

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
