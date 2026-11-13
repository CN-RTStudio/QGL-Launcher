package main

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
