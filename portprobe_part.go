package main

import (
	"errors"
	"net"
	"syscall"
)

func classifyBindError(err error) string {
	if err == nil {
		return portProbeFree
	}
	// Windows：WSAEADDRINUSE=10048、WSAEACCES=10013；
	// POSIX：EADDRINUSE、EACCES。net 包在多平台会把占用包装成 *net.OpError，
	// 先用 errors.Is 走标准语义，再兜底字符串 / syscall 判定。
	if errors.Is(err, syscall.EADDRINUSE) {
		return portProbeInUse
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return portProbePermission
	}
	if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) {
		return portProbeNotSupported
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return portProbeUnreachable
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return classifyBindError(opErr.Err)
	}
	// Windows 错误码无法通过 syscall.EADDRINUSE 命中时的兜底：依据系统错误号判断。
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		switch uintptr(sysErr) {
		case 10048: // WSAEADDRINUSE
			return portProbeInUse
		case 10013: // WSAEACCES
			return portProbePermission
		case 10047, 10043: // WSAEAFNOSUPPORT / WSAEPROTONOSUPPORT
			return portProbeNotSupported
		case 10051, 10065: // WSAENETUNREACH / WSAEHOSTUNREACH
			return portProbeUnreachable
		}
	}
	return portProbeUnknown
}
