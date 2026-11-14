package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

)

func (a *App) SetServerOnlineMode(name string, onlineMode bool) error {
	cfg, err := a.getServerConfig(name)
	if err != nil {
		return err
	}

	// 修改 server.properties
	propPath := filepath.Join(cfg.ServerDir, "server.properties")
	content := ""
	if data, err := os.ReadFile(propPath); err == nil {
		content = string(data)
	}

	lines := strings.Split(content, "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, "online-mode=") {
			lines[i] = "online-mode=" + strconv.FormatBool(onlineMode)
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, "online-mode="+strconv.FormatBool(onlineMode))
	}

	if err := os.WriteFile(propPath, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		return fmt.Errorf("修改 server.properties 失败: %v", err)
	}

	// 更新 QGL 配置
	cfg.OnlineMode = onlineMode
	qglDir := filepath.Join(cfg.ServerDir, "QGL")
	cfgData, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(filepath.Join(qglDir, "config.json"), cfgData, 0644)

	return nil
}

// GenerateConnectionCode 生成连接码和直连地址
func (a *App) GenerateConnectionCode(serverName string) (map[string]string, error) {
	cfg, err := a.getServerConfig(serverName)
	if err != nil {
		return nil, err
	}

	// 获取本机 IP
	ip, err := getLocalIP()
	if err != nil {
		return nil, fmt.Errorf("获取本机 IP 失败: %v", err)
	}

	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("IP 地址格式异常: %s", ip)
	}

	// 第一段映射
	firstSeg, _ := strconv.Atoi(parts[0])
	var prefix string
	switch {
	case firstSeg == 10:
		prefix = "A"
	case firstSeg == 172:
		prefix = "B"
	case firstSeg == 192:
		prefix = "C"
	case firstSeg == 1:
		prefix = "D"
	default:
		prefix = fmt.Sprintf("X%d", firstSeg)
	}

	// 第2、3、4段和端口转16进制
	seg2, _ := strconv.Atoi(parts[1])
	seg3, _ := strconv.Atoi(parts[2])
	seg4, _ := strconv.Atoi(parts[3])
	port := cfg.Port

	code := fmt.Sprintf("%s-%s-%s-%s-%s",
		prefix,
		strconv.FormatInt(int64(seg2), 16),
		strconv.FormatInt(int64(seg3), 16),
		strconv.FormatInt(int64(seg4), 16),
		strconv.FormatInt(int64(port), 16),
	)

	directAddr := fmt.Sprintf("%s:%d", ip, port)

	return map[string]string{
		"code":       code,
		"directAddr": directAddr,
	}, nil
}

// ParseConnectionCode 解析连接码
func (a *App) ParseConnectionCode(code string) (string, error) {
	parts := strings.Split(code, "-")
	if len(parts) != 5 {
		return "", fmt.Errorf("连接码格式错误")
	}

	// 解析前缀
	prefix := parts[0]
	var firstSeg int
	switch prefix {
	case "A":
		firstSeg = 10
	case "B":
		firstSeg = 172
	case "C":
		firstSeg = 192
	case "D":
		firstSeg = 1
	default:
		if strings.HasPrefix(prefix, "X") {
			val, err := strconv.Atoi(prefix[1:])
			if err != nil {
				return "", fmt.Errorf("连接码前缀无法解析")
			}
			firstSeg = val
		} else {
			return "", fmt.Errorf("连接码前缀无法解析")
		}
	}

	// 解析其余段
	seg2, err := strconv.ParseInt(parts[1], 16, 64)
	if err != nil {
		return "", fmt.Errorf("连接码第2段解析失败")
	}
	seg3, err := strconv.ParseInt(parts[2], 16, 64)
	if err != nil {
		return "", fmt.Errorf("连接码第3段解析失败")
	}
	seg4, err := strconv.ParseInt(parts[3], 16, 64)
	if err != nil {
		return "", fmt.Errorf("连接码第4段解析失败")
	}
	port, err := strconv.ParseInt(parts[4], 16, 64)
	if err != nil {
		return "", fmt.Errorf("连接码端口解析失败")
	}

	ip := fmt.Sprintf("%d.%d.%d.%d:%d", firstSeg, seg2, seg3, seg4, port)
	return ip, nil
}

// getLocalIP 获取本机局域网 IP
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

	// 如果正在运行，先停止
	serverMgr.mu.Lock()
	if serverMgr.status.Running && serverMgr.status.Name == name {
		serverMgr.mu.Unlock()
		a.StopServer()
		time.Sleep(1 * time.Second)
	} else {
		serverMgr.mu.Unlock()
	}

	return os.RemoveAll(cfg.ServerDir)
}
