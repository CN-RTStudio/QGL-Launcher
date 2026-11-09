package main

const (
	// 默认 / 兜底堆大小（GB），与 buildLaunchArgs 历史默认 "2G"/"1G" 保持一致。
	defaultHeapMaxGB = 2
	defaultHeapMinGB = 1
	// GB 口径上界：maxMemoryMBUpperBound 是 1<<20 MB = 1024 GB = 1 TiB。
	maxHeapGB = maxMemoryMBUpperBound / 1024
)

// 处置码：描述本次归一对原始输入做了什么，供调用方写安全审计。
const (
	heapCodeMaxZeroDefault = "heap-max-zero-default" // max<=0，回默认
	heapCodeMinZeroDefault = "heap-min-zero-default" // min<=0，回默认
	heapCodeMaxClamped     = "heap-max-clamped"      // max 超上界，收敛
	heapCodeMinClamped     = "heap-min-clamped"      // min 超上界，收敛
	heapCodeMinExceedsMax  = "heap-min-exceeds-max"  // min>max，收敛 min
)

// clampHeapGB 把单个堆大小（GB）归一到 [1,maxHeapGB]。
// 返回 (归一值, 是否使用了默认, 是否被上界收敛)。zeroOrNegative 时回 defaultGB。
func clampHeapGB(gb, defaultGB int) (int, bool, bool) {
	if gb <= 0 {
		return defaultGB, true, false
	}
	if gb > maxHeapGB {
		return maxHeapGB, false, true
	}
	return gb, false, false
}

// heapGBToMB 把归一后的 GB 换算为 MB（1024 倍），供需要 MB 口径的审计复用。
func heapGBToMB(gb int) int {
	if gb <= 0 {
		return 0
	}
	return gb * 1024
}
