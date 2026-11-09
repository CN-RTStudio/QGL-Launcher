package main

import "net"

func embeddedTransitionIPv4(ip net.IP) (net.IP, bool) {
	if len(ip) != net.IPv6len {
		return nil, false
	}
	nat64 := ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b
	if nat64 {
		for i := 4; i < 12; i++ {
			if ip[i] != 0 {
				nat64 = false
				break
			}
		}
		if nat64 {
			return net.IPv4(ip[12], ip[13], ip[14], ip[15]), true
		}
	}
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return net.IPv4(ip[2], ip[3], ip[4], ip[5]), true
	}
	compatible := true
	for i := 0; i < 12; i++ {
		if ip[i] != 0 {
			compatible = false
			break
		}
	}
	if compatible && (ip[12] != 0 || ip[13] != 0 || ip[14] != 0 || ip[15] != 0) {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]), true
	}
	teredo := ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00
	if teredo {
		raw := net.IPv4(ip[12], ip[13], ip[14], ip[15])
		v4 := raw.To4()
		return net.IPv4(v4[0]^0xff, v4[1]^0xff, v4[2]^0xff, v4[3]^0xff), true
	}
	return nil, false
}
