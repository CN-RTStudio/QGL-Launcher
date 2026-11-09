package main

import (
	"errors"
	"net"
	"syscall"
	"time"
)

// portprobe.go —— 服务器端口占用预检内核。
//
// 背景：
//   CreateServer 只校验端口在 1-65535、内存在区间内，从不检查端口是否已被其它进程
//   监听。结果用户创建服务器时一切正常，直到点“启动”，JVM 绑定失败才在日志里冒出
//   一句 "Perhaps a server is already running"，启动器却报告“已启动”，体验和排障都
//   很差。另一个常见坑是端口被占用时返回的错误因平台而异，需要归类成稳定原因码。
//
// 本模块：
//   - classifyBindError 把底层错误归成稳定原因码（纯函数可单测）；
//   - probeListenAddress 在指定地址上做一次“立即打开又关闭”的 TCP 监听试探；
//   - IsTCPPortAvailable 在服务器真实绑定的两类通配地址（0.0.0.0 / [::]）上分别探测，
//     因为另一个进程可能只占了 IPv4 或只占了 IPv6 的同一端口；
//   - 探测是“咨询性”的：探测结束到真正绑定之间存在天然 TOCTOU 窗口，无法消除，
//     因此 StartServer 仍以 JVM 实际绑定结果为准，预检只负责提前给出清晰错误。

// 端口探测原因码。
const (
	portProbeFree         = "free"           // 地址可绑定
	portProbeInUse        = "address-in-use" // 地址 / 端口已被占用
	portProbePermission   = "permission-denied"
	portProbeUnreachable  = "unreachable"
	portProbeInvalid      = "invalid-port"
	portProbeNotSupported = "not-supported"
	portProbeUnknown      = "unknown-error"
)

// 服务器应当绑定的通配地址。Minecraft 服务端默认监听所有网卡，因此只探测
// 127.0.0.1 会漏掉“别的进程占了对外地址”的情况，必须两类通配地址都试。
var wildcardProbeAddresses = []string{"0.0.0.0", "::"}

// PortProbeResult 是单个地址的探测结果。
type PortProbeResult struct {
	Address string `json:"address"`
	Free    bool   `json:"free"`
	Reason  string `json:"reason"`
}

// PortAvailability 是端口在全部通配地址上的综合结论。
type PortAvailability struct {
	Port    int               `json:"port"`
	Free    bool              `json:"free"`
	Reason  string            `json:"reason"`
	Details []PortProbeResult `json:"details"`
}

// probeDialTimeout 限制监听套接字创建的整体时长，正常本机绑定是毫秒级。
const probeListenTimeout = 2 * time.Second

// classifyBindError 把监听失败错误归成稳定原因码，供上层给出中文提示与单测断言。
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
