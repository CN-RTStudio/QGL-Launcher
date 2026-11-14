package main

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
