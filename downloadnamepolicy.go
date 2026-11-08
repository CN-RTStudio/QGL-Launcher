package main

import "strings"

const maxDownloadQueueNameLen = 120

const (
	dqNameRejectNone      = ""
	dqNameRejectEmpty     = "name-empty"
	dqNameRejectLong      = "name-too-long"
	dqNameRejectControl   = "name-control-char"
	dqNameRejectSeparator = "name-separator"
	dqNameRejectTraversal = "name-traversal"
	dqNameRejectReserved  = "name-reserved"
	dqNameRejectTrailing  = "name-trailing-dot"
)

var windowsReservedDeviceNames = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

func auditDownloadQueueName(raw string) string {
	if raw == "" {
		return dqNameRejectEmpty
	}
	if len(raw) > maxDownloadQueueNameLen {
		return dqNameRejectLong
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c < 0x20 || c == 0x7f {
			return dqNameRejectControl
		}
	}
	if strings.ContainsAny(raw, "/\\:*?\"<>|") {
		return dqNameRejectSeparator
	}
	trimmed := strings.TrimRight(raw, " .")
	if trimmed == "" {
		return dqNameRejectTrailing
	}
	if trimmed == "." || trimmed == ".." || strings.HasPrefix(trimmed, "..") {
		return dqNameRejectTraversal
	}
	if trimmed != raw {
		return dqNameRejectTrailing
	}
	stem := strings.ToLower(raw)
	if idx := strings.IndexByte(stem, '.'); idx >= 0 {
		stem = stem[:idx]
	}
	if windowsReservedDeviceNames[stem] {
		return dqNameRejectReserved
	}
	if windowsReservedDeviceNames[strings.ToLower(raw)] {
		return dqNameRejectReserved
	}
	return dqNameRejectNone
}

func describeDownloadNameReject(reason string) string {
	switch reason {
	case dqNameRejectNone:
		return "通过"
	case dqNameRejectEmpty:
		return "下载任务名称为空"
	case dqNameRejectLong:
		return "下载任务名称超过 120 字节上限"
	case dqNameRejectControl:
		return "下载任务名称含控制字符或 DEL"
	case dqNameRejectSeparator:
		return "下载任务名称含路径分隔符或 Windows 保留标点"
	case dqNameRejectTraversal:
		return "下载任务名称含 .. 路径穿越段"
	case dqNameRejectReserved:
		return "下载任务名称命中 Windows 保留设备名（CON/PRN/AUX/NUL/COM1-9/LPT1-9）"
	case dqNameRejectTrailing:
		return "下载任务名称以点或空格结尾"
	default:
		return "下载任务名称未通过安全校验"
	}
}
