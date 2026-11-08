package main

import (
	"net"
	"syscall"
	"testing"
)

func TestClassifyBindError(t *testing.T) {
	if r := classifyBindError(nil); r != portProbeFree {
		t.Errorf("nil 错误应为 free，got %s", r)
	}
	if r := classifyBindError(syscall.EADDRINUSE); r != portProbeInUse {
		t.Errorf("EADDRINUSE 应归类 in-use，got %s", r)
	}
	if r := classifyBindError(syscall.EACCES); r != portProbePermission {
		t.Errorf("EACCES 应归类 permission，got %s", r)
	}
	if r := classifyBindError(syscall.EPERM); r != portProbePermission {
		t.Errorf("EPERM 应归类 permission，got %s", r)
	}
	// *net.OpError 包裹时也要能解出内层原因。
	wrapped := &net.OpError{Op: "listen", Net: "tcp", Addr: nil, Err: syscall.EADDRINUSE}
	if r := classifyBindError(wrapped); r != portProbeInUse {
		t.Errorf("被 OpError 包裹的 EADDRINUSE 应归类 in-use，got %s", r)
	}
	// 无关错误落到 unknown，而不是被误判成占用。
	if r := classifyBindError(syscall.ENOENT); r != portProbeUnknown {
		t.Errorf("无关错误应归类 unknown，got %s", r)
	}
}

func TestDescribePortProbeReason(t *testing.T) {
	for _, code := range []string{
		portProbeFree, portProbeInUse, portProbePermission, portProbeUnreachable,
		portProbeInvalid, portProbeNotSupported, portProbeUnknown,
	} {
		if describePortProbeReason(code) == "" {
			t.Errorf("原因码 %s 缺少中文说明", code)
		}
	}
}

// freeTCPPort 让系统分配一个临时空闲端口并返回，监听套接字在用例结束后关闭。
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("分配测试端口失败: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("关闭临时监听失败: %v", err)
	}
	return port
}

func TestProbeListenAddressFree(t *testing.T) {
	port := freeTCPPort(t)
	r := probeListenAddress("127.0.0.1", port)
	if !r.Free || r.Reason != portProbeFree {
		t.Errorf("刚释放的临时端口应探测为空闲，got free=%v reason=%s", r.Free, r.Reason)
	}
}

func TestProbeListenAddressInUse(t *testing.T) {
	// 自己先占住 127.0.0.1:port，再探测同一地址，应当报占用。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	r := probeListenAddress("127.0.0.1", port)
	if r.Free || r.Reason != portProbeInUse {
		t.Errorf("已监听端口应报 address-in-use，got free=%v reason=%s", r.Free, r.Reason)
	}
}

func TestProbeInvalidPort(t *testing.T) {
	for _, bad := range []int{0, -1, 70000, 65536} {
		r := probeListenAddress("127.0.0.1", bad)
		if r.Free || r.Reason != portProbeInvalid {
			t.Errorf("非法端口 %d 应报 invalid，got free=%v reason=%s", bad, r.Free, r.Reason)
		}
	}
	avail := IsTCPPortAvailable(0)
	if avail.Free || avail.Reason != portProbeInvalid {
		t.Errorf("IsTCPPortAvailable(0) 应为 invalid，got free=%v reason=%s", avail.Free, avail.Reason)
	}
}

func TestIsTCPPortAvailableBlockedWhenBound(t *testing.T) {
	// 占住 IPv4 通配地址后，整体可用性必须为 false，即使某些双栈环境下 IPv6 探测空闲。
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("无法监听 0.0.0.0 进行占用测试: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	avail := IsTCPPortAvailable(port)
	if avail.Free {
		t.Errorf("端口 %d 已在 0.0.0.0 被占用，综合结论应为不可用；details=%+v", port, avail.Details)
	}
	if avail.Reason == portProbeFree {
		t.Error("占用时综合原因码不应仍是 free")
	}
}
