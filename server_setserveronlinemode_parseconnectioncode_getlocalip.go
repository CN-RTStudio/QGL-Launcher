package main

import (
	"net"

)

func getLocalIP() (string, error) {
	// UDP 探测法：向外网发一个 UDP 包，让操作系统选择默认网关对应的网卡
	// UDP 不需要握手，不会产生真实流量
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		// 备选方案：遍历网卡法
		return getLocalIPByInterface(), nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// getLocalIPByInterface 备选方案：遍历网卡获取局域网 IP
