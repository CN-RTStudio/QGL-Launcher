package main

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
