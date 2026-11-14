package main

import (
	"errors"
	"net"
	"syscall"
	"time"
)

const (
	portProbeFree         = "free"           // 地址可绑定
	portProbeInUse        = "address-in-use" // 地址 / 端口已被占用
	portProbePermission   = "permission-denied"
	portProbeUnreachable  = "unreachable"
	portProbeInvalid      = "invalid-port"
	portProbeNotSupported = "not-supported"
	portProbeUnknown      = "unknown-error"
)

var wildcardProbeAddresses = []string{"0.0.0.0", "::"}

type PortProbeResult struct {
	Address string `json:"address"`
	Free    bool   `json:"free"`
	Reason  string `json:"reason"`
}
type PortAvailability struct {
	Port    int               `json:"port"`
	Free    bool              `json:"free"`
	Reason  string            `json:"reason"`
	Details []PortProbeResult `json:"details"`
}

const probeListenTimeout = 2 * time.Second

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
