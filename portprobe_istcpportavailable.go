package main

import ()

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
