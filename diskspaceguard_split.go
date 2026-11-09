package main

import (
	"math"
)

// assessDiskFit 是落盘前的核心裁决：给定当前可用字节、本次写入字节、在途预留字节，
// 判断写完后是否仍保留安全水位。纯函数，不碰文件系统。
//
//	available<0            -> unknown（探测失败，不误杀）
//	requested/inflight<0   -> bad-input
//	need 溢出 int64        -> bad-input（物理上不可能的声明，拒绝而非写成回绕负数）
//	写完后 < 安全水位       -> short，并给出 Shortfall
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

// FormatBytes 把字节数渲染成人类可读字符串，用于错误提示与安全事件明细。
// 负数（未知）返回 "未知"。这里不引第三方依赖，二进制单位（1024）与磁盘口径一致。
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

// formatScaled 用一位小数渲染换算后的值；正好整除时不带小数，避免 "1.0 GiB" 啰嗦。
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
