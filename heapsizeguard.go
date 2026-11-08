package main

// heapsizeguard.go —— 游戏启动 JVM 堆大小（-Xms / -Xmx）的最终拼接点收口内核。
//
// 威胁模型：
//   GlobalConfig.MaxMemory / MinMemory 由前端经 Wails 的 SaveGlobalConfig 直接落盘，
//   该保存路径对这两个整数不做任何校验（对比：服务端 CreateServer 会走 isValidMemory
//   并检查 min<=max）。buildLaunchArgs 又直接
//     maxMem = fmt.Sprintf("%dG", config.MaxMemory)
//     "-Xmx"+maxMem, "-Xms"+minMem
//   于是被篡改 / 误填的配置会原样进入 java 命令行：
//     - 0 / 负数      -> "-Xmx0G" / "-Xmx-4G"，JVM 直接拒绝启动；
//     - 极大值        -> "-Xmx1000000G"，超过物理内存与地址空间，启动即失败；
//     - min > max     -> "-Xms" 大于 "-Xmx"，JVM 启动报错；
//     - 非预期整数    -> 没有任何审计痕迹，难以排查“为什么突然起不来”。
//   配置文件虽在本机，但属于跨信任边界的外部数据（可被手改 / 同步 / 旧版本写脏）。
//   本内存在“拼命令行的最后一步”做纯函数归一：零 / 负值回默认、越界收敛、min 不得
//   大于 max，并返回机器可读的处置码供安全审计。单位沿用既有游戏路径的 GB（默认
//   2G/1G），与服务端配置的 MB 口径相互独立；GB 上界与 launchtarget 的
//   maxMemoryMBUpperBound（1 TiB）对齐。纯函数、无 IO，便于穷举单测。

import "strconv"

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
