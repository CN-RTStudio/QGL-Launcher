package main

import (
	"net"
	"strconv"
	"time"
)

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
