package main

import (
	"math"
)

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
