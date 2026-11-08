package main

import (
	"errors"
	"net"
	"strconv"
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
	portProbeFree          = "free"           // 地址可绑定
	portProbeInUse         = "address-in-use" // 地址 / 端口已被占用
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

// probeListenAddress 在 host:port 上尝试监听一次再立即关闭，返回该地址是否空闲。
// 不持有套接字，避免影响随后 JVM 的真实绑定。
func probeListenAddress(host string, port int) PortProbeResult {
	res := PortProbeResult{Address: net.JoinHostPort(host, strconv.Itoa(port))}
	if !isValidPort(port) {
		res.Free = false
		res.Reason = portProbeInvalid
		return res
	}
	// 用带超时的拨号控制上下文不可用于 Listen；本机 bind 不受网络 RTT 影响，
	// 设置一个截止时间通道仅用于在异常环境下避免 goroutine 滞留。Listen 本身是同步的。
	done := make(chan struct{})
	lnCh := make(chan net.Listener, 1)
	errCh := make(chan error, 1)
	go func() {
		ln, lerr := net.Listen("tcp", res.Address)
		close(done)
		if lerr != nil {
			errCh <- lerr
			return
		}
		lnCh <- ln
	}()
	select {
	case ln := <-lnCh:
		_ = ln.Close()
		res.Free = true
		res.Reason = portProbeFree
	case err := <-errCh:
		res.Free = false
		res.Reason = classifyBindError(err)
	case <-time.After(probeListenTimeout):
		res.Free = false
		res.Reason = portProbeUnknown
	}
	return res
}

// IsTCPPortAvailable 在服务器将要绑定的所有通配地址上探测端口。
// 任一通配地址报“占用 / 权限拒绝”即判定端口不可用；某协议族不受支持（纯 IPv4
// 环境无 IPv6）不算占用，跳过该地址继续。
func IsTCPPortAvailable(port int) PortAvailability {
	out := PortAvailability{Port: port, Free: true, Reason: portProbeFree}
	if !isValidPort(port) {
		out.Free = false
		out.Reason = portProbeInvalid
		return out
	}
	for _, host := range wildcardProbeAddresses {
		r := probeListenAddress(host, port)
		out.Details = append(out.Details, r)
		switch r.Reason {
		case portProbeFree, portProbeNotSupported:
			// 空闲或该协议族不存在：不影响可用性结论。
			continue
		default:
			// 占用 / 权限 / 不可达 / 未知：端口不能安全用于新服务器。
			out.Free = false
			if out.Reason == portProbeFree {
				out.Reason = r.Reason
			}
		}
	}
	return out
}

// describePortProbeReason 把原因码转成面向用户的中文说明。
func describePortProbeReason(reason string) string {
	switch reason {
	case portProbeFree:
		return "端口可用"
	case portProbeInUse:
		return "端口已被其它程序占用，请更换端口或关闭占用程序"
	case portProbePermission:
		return "系统拒绝绑定该端口（权限不足或被策略保留）"
	case portProbeUnreachable:
		return "当前网络环境无法绑定该端口"
	case portProbeInvalid:
		return "端口号无效"
	case portProbeNotSupported:
		return "当前系统不支持该端口绑定方式"
	default:
		return "无法确定端口是否可用"
	}
}
