package main

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
