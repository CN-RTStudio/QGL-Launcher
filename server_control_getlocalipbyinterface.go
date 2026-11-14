package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

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

func (a *App) validateLoadedServerConfig(cfg *ServerConfig) error {
	if cfg == nil {
		return fmt.Errorf("空服务器配置")
	}
	if sanitizeServerName(cfg.Name) == "" {
		return fmt.Errorf("无效的服务器名称: %q", cfg.Name)
	}
	if err := sanitizePathComponent(cfg.Version); err != nil {
		return fmt.Errorf("无效的版本号: %v", err)
	}
	if !isValidPort(cfg.Port) {
		return fmt.Errorf("无效的端口号: %d", cfg.Port)
	}
	if !isValidMemory(cfg.MaxMemory) || !isValidMemory(cfg.MinMemory) {
		return fmt.Errorf("无效的内存配置")
	}
	if cfg.MinMemory > cfg.MaxMemory {
		return fmt.Errorf("最小内存不能大于最大内存")
	}
	serverRoot := filepath.Clean(a.GetServerDir())
	dir := filepath.Clean(cfg.ServerDir)
	if dir == "" || !filepath.IsAbs(dir) || isPathTraversal(serverRoot, dir) {
		return fmt.Errorf("服务器目录越界或非法: %q", cfg.ServerDir)
	}
	return nil
}

func (a *App) getServerConfig(name string) (*ServerConfig, error) {
	if err := sanitizePathComponent(name); err != nil {
		return nil, fmt.Errorf("无效的服务器名称")
	}
	serverDir := a.GetServerDir()
	configPath := filepath.Join(serverDir, name, "QGL", "config.json")
	var cfg ServerConfig
	if err := readPrivateStoreJSON(configPath, &cfg, "服务器配置"); err != nil {
		list, listErr := a.GetServerList()
		if listErr != nil {
			return nil, fmt.Errorf("读取配置失败: %v", listErr)
		}
		for i := range list {
			if list[i].Name == name {
				return &list[i], nil
			}
		}
		return nil, fmt.Errorf("找不到服务器 %s", name)
	}
	// 加载即校验：拒绝被篡改 / 写坏的配置进入后续 java -jar 执行路径。
	if err := a.validateLoadedServerConfig(&cfg); err != nil {
		return nil, fmt.Errorf("服务器配置不安全: %v", err)
	}
	return &cfg, nil
}
