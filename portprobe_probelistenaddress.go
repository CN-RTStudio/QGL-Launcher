package main

import (
	"net"
	"strconv"
	"time"
)

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
