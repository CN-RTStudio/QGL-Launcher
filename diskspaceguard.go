package main

import (
	"math"
)

const diskReserveHeadroomBytes int64 = 1 << 30
const diskAvailUnknown int64 = -1

type diskFitVerdict string

const (
	diskFitOK       diskFitVerdict = "ok"        // 写入后仍高于安全水位
	diskFitShort    diskFitVerdict = "short"     // 写入会击穿安全水位（会炸盘）
	diskFitBadInput diskFitVerdict = "bad-input" // 入参为负或非法
	diskFitUnknown  diskFitVerdict = "unknown"   // 无法探测剩余空间，保守放行
)

type DiskFitAssessment struct {
	Verdict    diskFitVerdict
	Available  int64 // 当前可用字节；探测失败为 diskAvailUnknown
	Requested  int64 // 本次新申请写入字节
	Inflight   int64 // 已排队但尚未落盘、需预留的字节
	Need       int64 // Requested+Inflight（未做溢出折叠时为 -1）
	AfterWrite int64 // 预计写入完成后的剩余字节（未知时为 diskAvailUnknown）
	Shortfall  int64 // 距安全水位还差多少字节（仅 short 时 >0）
}

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

func assessDiskFit(available, requested, inflight int64) DiskFitAssessment {
	r := DiskFitAssessment{
		Available:  available,
		Requested:  requested,
		Inflight:   inflight,
		AfterWrite: diskAvailUnknown,
	}
	if available == diskAvailUnknown || available < 0 {
		r.Verdict = diskFitUnknown
		r.Need = diskAvailUnknown
		return r
	}
	req, okR := normalizeNonNegative(requested)
	inflight2, okI := normalizeNonNegative(inflight)
	if !okR || !okI {
		r.Verdict = diskFitBadInput
		return r
	}
	need, ok := addChecked(req, inflight2)
	if !ok {
		r.Verdict = diskFitBadInput
		r.Need = -1
		return r
	}
	r.Need = need
	// available>=0 且 need 合法：AfterWrite 不会为正溢出，但若 available<need
	// 直接相减会得到负数（表示本来就不够），这是预期信号，单独判 short。
	if available < need {
		after := need - available // 缺口的正值
		r.AfterWrite = -(after)
		r.Verdict = diskFitShort
		r.Shortfall = after + diskReserveHeadroomBytes
		if r.Shortfall < 0 {
			r.Shortfall = math.MaxInt64
		}
		return r
	}
	after := available - need
	r.AfterWrite = after
	if after < diskReserveHeadroomBytes {
		r.Verdict = diskFitShort
		r.Shortfall = diskReserveHeadroomBytes - after
		return r
	}
	r.Verdict = diskFitOK
	return r
}

// describeDiskFit 把裁决结论转成中文说明（unknown 给空串，由调用方按放行处理）。
func describeDiskFit(a DiskFitAssessment) string {
	switch a.Verdict {
	case diskFitShort:
		return "磁盘剩余空间不足，下载会把可用空间耗尽，已阻止（" +
			FormatBytes(a.Shortfall) + "）"
	case diskFitBadInput:
		return "下载字节数声明非法"
	default:
		return ""
	}
}

const (
	unitKiB = 1 << 10
	unitMiB = 1 << 20
	unitGiB = 1 << 30
	unitTiB = 1 << 40
)

func FormatBytes(n int64) string {
	if n < 0 {
		return "未知"
	}
	switch {
	case n >= unitTiB:
		return formatScaled(n, unitTiB, "TiB")
	case n >= unitGiB:
		return formatScaled(n, unitGiB, "GiB")
	case n >= unitMiB:
		return formatScaled(n, unitMiB, "MiB")
	case n >= unitKiB:
		return formatScaled(n, unitKiB, "KiB")
	default:
		return itoa64(n) + " B"
	}
}

func formatScaled(n, unit int64, suffix string) string {
	whole := n / unit
	rem := n % unit
	if rem == 0 {
		return itoa64(whole) + " " + suffix
	}
	tenths := (rem * 10) / unit
	if tenths < 1 {
		tenths = 1
	}
	if tenths >= 10 {
		tenths = 9
	}
	return itoa64(whole) + "." + itoa64(tenths) + " " + suffix
}

// itoa64 是最小依赖的非负整数转字符串（避免为一处格式化再引 strconv 到纯内核，
// 同时让本文件保持零外部 import 之外的行为可预测）。
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [32]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
