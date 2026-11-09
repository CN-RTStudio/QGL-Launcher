package main

import (
	"strconv"
)

// ResolveHeapSizesGB 归一游戏堆配置（单位 GB），返回可安全拼接的 (minGB,maxGB) 与
// 处置码列表。规则：
//   - max<=0 回默认 2G；min<=0 回默认 1G；
//   - 任一超过 1 TiB 上界则收敛到上界；
//   - 归一后若 min>max（含 max 被收敛到比 min 小），把 min 收敛到不超过 max
//     （至少 1G）；
//   - 始终保证 1 <= min <= max <= maxHeapGB。
func ResolveHeapSizesGB(minGB, maxGB int) (int, int, []string) {
	codes := make([]string, 0, 4)

	maxVal, maxDefaulted, maxClamped := clampHeapGB(maxGB, defaultHeapMaxGB)
	if maxDefaulted {
		codes = append(codes, heapCodeMaxZeroDefault)
	}
	if maxClamped {
		codes = append(codes, heapCodeMaxClamped)
	}

	minVal, minDefaulted, minClamped := clampHeapGB(minGB, defaultHeapMinGB)
	if minDefaulted {
		codes = append(codes, heapCodeMinZeroDefault)
	}
	if minClamped {
		codes = append(codes, heapCodeMinClamped)
	}

	// 顺序约束：-Xms 不得大于 -Xmx。max 可能因上界收敛而小于原始 min，这里统一收敛。
	if minVal > maxVal {
		minVal = maxVal
		if minVal < 1 {
			minVal = 1
		}
		codes = append(codes, heapCodeMinExceedsMax)
	}
	return minVal, maxVal, codes
}

// FormatHeapSizeGB 把已归一的 GB 正整数格式化为 JVM 大小串（如 2 -> "2G"）。
// 仅接受正数；对非正输入回退到默认 2G，避免产出 "-Xmx0G" 这类非法参数。
func FormatHeapSizeGB(gb int) string {
	if gb <= 0 {
		gb = defaultHeapMaxGB
	}
	if gb > maxHeapGB {
		gb = maxHeapGB
	}
	return strconv.Itoa(gb) + "G"
}

// BuildJVMHeapArgs 一次性产出可直接放入命令行的 (-Xms, -Xmx) 两个参数，
// 以及处置码。供 buildLaunchArgs 在最终拼接点调用，杜绝绕过归一的可能。
func BuildJVMHeapArgs(minGB, maxGB int) (xms, xmx string, minOut, maxOut int, codes []string) {
	minOut, maxOut, codes = ResolveHeapSizesGB(minGB, maxGB)
	return "-Xms" + FormatHeapSizeGB(minOut), "-Xmx" + FormatHeapSizeGB(maxOut),
		minOut, maxOut, codes
}
