package main

import (
	"math"
)

// diskReserveHeadroomBytes 是无论如何都要保留、不许下载占满的最小空闲水位（1GiB）。
// 低于这条线就拒绝，给系统页文件 / 日志 / 其它程序留出生存空间。
const diskReserveHeadroomBytes int64 = 1 << 30

// diskAvailUnknown 表示平台层未能取到剩余字节（调用失败）。
const diskAvailUnknown int64 = -1

// 磁盘裁决结论码。
type diskFitVerdict string

const (
	diskFitOK       diskFitVerdict = "ok"        // 写入后仍高于安全水位
	diskFitShort    diskFitVerdict = "short"     // 写入会击穿安全水位（会炸盘）
	diskFitBadInput diskFitVerdict = "bad-input" // 入参为负或非法
	diskFitUnknown  diskFitVerdict = "unknown"   // 无法探测剩余空间，保守放行
)

// DiskFitAssessment 是一次“这批字节能不能落盘”的裁决结果。
type DiskFitAssessment struct {
	Verdict    diskFitVerdict
	Available  int64 // 当前可用字节；探测失败为 diskAvailUnknown
	Requested  int64 // 本次新申请写入字节
	Inflight   int64 // 已排队但尚未落盘、需预留的字节
	Need       int64 // Requested+Inflight（未做溢出折叠时为 -1）
	AfterWrite int64 // 预计写入完成后的剩余字节（未知时为 diskAvailUnknown）
	Shortfall  int64 // 距安全水位还差多少字节（仅 short 时 >0）
}

// normalizeNonNegative 把任何负数 / NaN 类输入折叠成“非法”。
// 调用方给的是字节数，负数没有物理意义，溢出求和也必须被识别。
func normalizeNonNegative(v int64) (int64, bool) {
	if v < 0 {
		return 0, false
	}
	return v, true
}

// addChecked 做带溢出检测的非负加法：和超过 math.MaxInt64 时返回 ok=false。
func addChecked(a, b int64) (int64, bool) {
	if a < 0 || b < 0 {
		return 0, false
	}
	if a > math.MaxInt64-b {
		return math.MaxInt64, false
	}
	return a + b, true
}

// sumNonNegativeBytes 对一批“声明字节数”求和。
// 约定：size<=0 表示“大小未知”，按 0 计入（不能因为服务端没给 Content-Length 就拒绝）；
// 任一显式正值导致总和溢出 63 位时返回 overflow=true，调用方按“可疑的天文数字”处理。
func sumNonNegativeBytes(sizes []int64) (int64, bool) {
	var total int64
	for _, s := range sizes {
		if s <= 0 {
			continue
		}
		sum, ok := addChecked(total, s)
		if !ok {
			return math.MaxInt64, true
		}
		total = sum
	}
	return total, false
}
