package main

import (
	"errors"
	"net"
	"strconv"
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
	return rejectReasonText(reason, "无法确定端口是否可用", describePortProbeReasonTexts)
}
