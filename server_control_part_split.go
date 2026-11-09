package main

import (
	"fmt"
	"net"
	"os"
)

// getLocalIP 获取本机局域网 IP
func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return getLocalIPByInterface(), nil
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// getLocalIPByInterface 备选方案：遍历网卡获取局域网 IP
func getLocalIPByInterface() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	return "127.0.0.1"
}

// DeleteServer 删除服务器
func (a *App) DeleteServer(name string) error {
	cfg, err := a.getServerConfig(name)
	if err != nil {
		return err
	}
	serverMgr.mu.Lock()
	if serverMgr.status.Running && serverMgr.status.Name == name {
		serverMgr.mu.Unlock()
		a.StopServer()
		if !waitForServerStop(serverStillRunning, serverExitWaitTimeout, serverExitPollInterval) {
			a.writeSecurityLog("删除服务器前进程未在超时内退出，拒绝删除目录: " + name)
			return fmt.Errorf("服务器进程仍在退出中，拒绝删除")
		}
	} else {
		serverMgr.mu.Unlock()
	}
	serverDir := a.GetServerDir()
	// 必须是严格子目录且解析符号链接后仍在根内，防止配置被改成根目录本身
	// 或指向外部的链接，导致 RemoveAll 清空所有服务器 / 删除越界路径。
	if !isStrictSubdir(serverDir, cfg.ServerDir) {
		return fmt.Errorf("服务器目录路径不安全（必须是服务器根目录的子目录），拒绝删除")
	}
	return os.RemoveAll(cfg.ServerDir)
}

func (a *App) writeSecurityLog(message string) {
	a.writeLog("[security] %s", message)
}
