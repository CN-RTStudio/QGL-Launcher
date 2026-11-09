package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SetServerOnlineMode 设置服务器正版验证
func (a *App) SetServerOnlineMode(name string, onlineMode bool) error {
	cfg, err := a.getServerConfig(name)
	if err != nil {
		return err
	}
	if isPathTraversal(a.GetServerDir(), cfg.ServerDir) {
		return fmt.Errorf("服务器目录路径不安全，拒绝修改")
	}
	propPath := filepath.Join(cfg.ServerDir, "server.properties")
	// 用保序、去重复键、校验布尔值的读写器替换原先的朴素行拆分，
	// 避免 CRLF 漏匹配 / 重复 online-mode 键冲突 / 非法值写入。
	if err := updateServerProperty(propPath, "online-mode", strconv.FormatBool(onlineMode), validateBoolProperty); err != nil {
		return err
	}
	cfg.OnlineMode = onlineMode
	qglDir := filepath.Join(cfg.ServerDir, "QGL")
	cfgData, _ := json.MarshalIndent(cfg, "", "  ")
	if err := secureWritePrivateFile(filepath.Join(qglDir, "config.json"), cfgData); err != nil {
		return fmt.Errorf("同步配置失败: %v", err)
	}
	return nil
}

// GenerateConnectionCode 生成连接码和直连地址
func (a *App) GenerateConnectionCode(serverName string) (map[string]string, error) {
	cfg, err := a.getServerConfig(serverName)
	if err != nil {
		return nil, err
	}
	ip, err := getLocalIP()
	if err != nil {
		return nil, fmt.Errorf("获取本机 IP 失败: %v", err)
	}
	// 生成侧也走严格 IPv4 归一：本机网卡返回的地址必须是合法四段 IPv4，
	// 否则宁可不生成连接码，也不把脏地址编进码里。
	normIP, ok := NormalizeIPv4(strings.TrimSpace(ip))
	if !ok {
		return nil, fmt.Errorf("IP 地址格式异常: %s", ip)
	}
	if !isValidPort(cfg.Port) {
		return nil, fmt.Errorf("服务器端口号无效: %d", cfg.Port)
	}
	// 编码统一交给连接码内核，保证“编得出就解得回”，不再在本方法内手拼。
	code, why := EncodeConnectionCode(normIP, cfg.Port)
	if why != connRejectNone {
		return nil, fmt.Errorf("生成连接码失败: %s", describeConnReject(why))
	}
	directAddr := fmt.Sprintf("%s:%d", normIP, cfg.Port)
	return map[string]string{
		"code":       code,
		"directAddr": directAddr,
	}, nil
}

// ParseConnectionCode 解析连接码。
// 安全加固: 解析逻辑全部收敛到 connectioncodeguard 纯函数内核——
// 首段（含 X<n>）严格 0-255 与位数限制，后三段十六进制 0-255，端口走统一
// isValidPort，末端再过 netaddrguard 形态校验。畸形连接码（X999 / X-1 / 超长
// 前缀 / 越界段或端口）一律拒绝并留审计，绝不返回半残地址。
func (a *App) ParseConnectionCode(code string) (string, error) {
	address, why := DecodeConnectionCode(strings.TrimSpace(code))
	if why != connRejectNone {
		recordSecurityEvent(auditCategoryConfig, auditSeverityWarn, auditActionRejected,
			"server", "拒绝畸形局域网连接码("+why+")")
		return "", fmt.Errorf("%s", describeConnReject(why))
	}
	return address, nil
}

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
