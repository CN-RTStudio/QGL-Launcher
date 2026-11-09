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
