package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ServerConfig 服务器配置
type ServerConfig struct {
	Name       string `json:"name"`       // 服务器名称
	Version    string `json:"version"`    // MC 版本
	Port       int    `json:"port"`       // 端口
	MaxMemory  int    `json:"maxMemory"`  // 最大内存 MB
	MinMemory  int    `json:"minMemory"`  // 最小内存 MB
	OnlineMode bool   `json:"onlineMode"` // 正版验证
	ServerDir  string `json:"serverDir"`  // 服务器目录
}

// ServerStatus 服务器运行状态
type ServerStatus struct {
	Running bool   `json:"running"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Port    int    `json:"port"`
	PID     int    `json:"pid"`
	Ready   bool   `json:"ready"` // 是否启动完毕
}

// ServerManager 服务器管理器
type ServerManager struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	status    ServerStatus
	logBuffer []string
	ctx       context.Context
	readyCh   chan struct{} // 服务器启动完毕信号
}

var serverMgr ServerManager

// GetServerDir 获取服务器根目录
func (a *App) GetServerDir() string {
	return filepath.Join(a.GetQGLDir(), "server")
}

// GetServerList 获取服务器列表
func (a *App) GetServerList() ([]ServerConfig, error) {
	serverDir := a.GetServerDir()
	if _, err := os.Stat(serverDir); os.IsNotExist(err) {
		return []ServerConfig{}, nil
	}

	entries, err := os.ReadDir(serverDir)
	if err != nil {
		return nil, err
	}

	var list []ServerConfig
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		configPath := filepath.Join(serverDir, entry.Name(), "QGL", "config.json")
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}
		var cfg ServerConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			continue
		}
		list = append(list, cfg)
	}
	return list, nil
}

// CreateServer 创建服务器
func (a *App) CreateServer(name, version string, port, maxMem, minMem int, onlineMode bool, customDir string) error {
	serverDir := a.GetServerDir()
	var dir string
	if customDir != "" {
		dir = customDir
	} else {
		dir = filepath.Join(serverDir, name)
	}

	// 创建目录
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建服务器目录失败: %v", err)
	}

	// 保存 QGL 配置
	qglDir := filepath.Join(dir, "QGL")
	if err := os.MkdirAll(qglDir, 0755); err != nil {
		return fmt.Errorf("创建 QGL 配置目录失败: %v", err)
	}

	cfg := ServerConfig{
		Name:       name,
		Version:    version,
		Port:       port,
		MaxMemory:  maxMem,
		MinMemory:  minMem,
		OnlineMode: onlineMode,
		ServerDir:  dir,
	}

	cfgData, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(filepath.Join(qglDir, "config.json"), cfgData, 0644); err != nil {
		return fmt.Errorf("保存配置失败: %v", err)
	}

	// 下载服务器 JAR
	if err := a.downloadServerJar(version, dir); err != nil {
		return fmt.Errorf("下载服务器文件失败: %v", err)
	}

	// 预创建 eula.txt
	if err := os.WriteFile(filepath.Join(dir, "eula.txt"), []byte("# By changing the setting below to TRUE you are indicating your agreement to our EULA (https://aka.ms/MinecraftEULA).\neula=true\n"), 0644); err != nil {
		return fmt.Errorf("创建 eula.txt 失败: %v", err)
	}

	// 预创建 server.properties
	properties := fmt.Sprintf("server-port=%d\nonline-mode=%v\nmotd=%s\n", port, onlineMode, name)
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(properties), 0644); err != nil {
		return fmt.Errorf("创建 server.properties 失败: %v", err)
	}

	return nil
}

// downloadServerJar 下载服务器 JAR 文件（参考 PCL 逻辑）
func (a *App) downloadServerJar(version string, targetDir string) error {
	jarPath := filepath.Join(targetDir, version+"-server.jar")

	// 如果已存在则跳过
	if _, err := os.Stat(jarPath); err == nil {
		return nil
	}

	// 1. 获取版本 JSON URL
	manifest, err := a.GetVersionManifest()
	if err != nil {
		return fmt.Errorf("获取版本清单失败: %v", err)
	}

	var versionURL string
	for _, v := range manifest {
		if v.ID == version {
			versionURL = v.URL
			break
		}
	}
	if versionURL == "" {
		return fmt.Errorf("找不到版本 %s", version)
	}

	// 替换为 BMCLAPI 镜像
	versionURL = strings.Replace(versionURL, "https://piston-meta.mojang.com", "https://bmclapi2.bangbang93.com", 1)
	versionURL = strings.Replace(versionURL, "https://launcher.mojang.com", "https://bmclapi2.bangbang93.com", 1)

	// 2. 下载版本 JSON
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(versionURL)
	if err != nil {
		return fmt.Errorf("下载版本 JSON 失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var versionJSON map[string]interface{}
	if err := json.Unmarshal(body, &versionJSON); err != nil {
		return fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	// 3. 从 JSON 中提取 server 下载地址
	downloads, ok := versionJSON["downloads"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("版本 JSON 中没有 downloads 字段")
	}
	server, ok := downloads["server"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("Mojang 没有为 %s 提供官方服务端下载", version)
	}

	jarURL, _ := server["url"].(string)
	if jarURL == "" {
		return fmt.Errorf("无法获取服务端下载地址")
	}

	// 替换为 BMCLAPI 镜像
	jarURL = strings.Replace(jarURL, "https://piston-data.mojang.com", "https://bmclapi2.bangbang93.com", 1)
	jarURL = strings.Replace(jarURL, "https://launcher.mojang.com", "https://bmclapi2.bangbang93.com", 1)

	// 4. 下载 JAR 文件
	downloadClient := &http.Client{Timeout: 120 * time.Second}
	dlResp, err := downloadClient.Get(jarURL)
	if err != nil {
		return fmt.Errorf("下载服务端 JAR 失败: %v", err)
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != 200 {
		return fmt.Errorf("下载服务端 JAR 失败 (HTTP %d)", dlResp.StatusCode)
	}

	file, err := os.Create(jarPath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	if _, err := io.Copy(file, dlResp.Body); err != nil {
		os.Remove(jarPath)
		return fmt.Errorf("写入文件失败: %v", err)
	}

	return nil
}

// StartServer 启动服务器
func (a *App) StartServer(name string) error {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()

	if serverMgr.status.Running {
		return fmt.Errorf("服务器已在运行中")
	}

	// 读取配置
	cfg, err := a.getServerConfig(name)
	if err != nil {
		return err
	}

	// 选择 Java
	javaEntry, err := a.SelectJavaForVersion(cfg.Version)
	if err != nil {
		return fmt.Errorf("选择 Java 失败: %v", err)
	}
	javaPath := javaEntry.Path

	// 构建启动命令
	jarName := cfg.Version + "-server.jar"
	maxMem := fmt.Sprintf("%dM", cfg.MaxMemory)
	minMem := fmt.Sprintf("%dM", cfg.MinMemory)

	args := []string{
		"-server",
		"-XX:+UseG1GC",
		fmt.Sprintf("-Xmx%s", maxMem),
		fmt.Sprintf("-Xms%s", minMem),
		"-XX:+UseCompressedOops",
		"-jar", jarName,
		"nogui",
	}

	// 构建 CmdLine
	var cmdLineParts []string
	cmdLineParts = append(cmdLineParts, quoteWindowsArg(javaPath))
	for _, arg := range args {
		if err := validateJavaArg(arg); err != nil {
			return fmt.Errorf("非法的服务器启动参数 %q: %v", arg, err)
		}
		cmdLineParts = append(cmdLineParts, quoteWindowsArg(arg))
	}
	fullCmdLine := strings.Join(cmdLineParts, " ")

	cmd := exec.Command(javaPath)
	cmd.Dir = cfg.ServerDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		CmdLine:    fullCmdLine,
	}

	// 获取 stdin pipe
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("获取 stdin 失败: %v", err)
	}

	// 获取 stdout pipe
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("获取 stdout 失败: %v", err)
	}

	// 获取 stderr pipe
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("获取 stderr 失败: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动服务器失败: %v", err)
	}

	// 初始化 ready Channel
	readyCh := make(chan struct{}, 1)

	serverMgr.cmd = cmd
	serverMgr.stdin = stdin
	serverMgr.logBuffer = make([]string, 0)
	serverMgr.ctx = a.ctx
	serverMgr.readyCh = readyCh
	serverMgr.status = ServerStatus{
		Running: true,
		Name:    name,
		Version: cfg.Version,
		Port:    cfg.Port,
		PID:     cmd.Process.Pid,
		Ready:   false,
	}

	// 读取日志
	go func() {
		scanner := make(chan string, 200)

		// stdout
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := stdout.Read(buf)
				if err != nil {
					return
				}
				lines := strings.Split(string(buf[:n]), "\n")
				for _, line := range lines {
					line = strings.TrimRight(line, "\r")
					if line != "" {
						scanner <- line
					}
				}
			}
		}()

		// stderr
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := stderr.Read(buf)
				if err != nil {
					return
				}
				lines := strings.Split(string(buf[:n]), "\n")
				for _, line := range lines {
					line = strings.TrimRight(line, "\r")
					if line != "" {
						scanner <- line
					}
				}
			}
		}()

		for line := range scanner {
			serverMgr.mu.Lock()
			serverMgr.logBuffer = append(serverMgr.logBuffer, line)
			if len(serverMgr.logBuffer) > 500 {
				serverMgr.logBuffer = serverMgr.logBuffer[len(serverMgr.logBuffer)-500:]
			}

			// 检测服务器启动完毕（中英文服务端特征字符串）
			if !serverMgr.status.Ready {
				// 英文端：Done (x.xxxs)! For help, type "help"
				// 中文端：完成 (x.xxxs)! 如需帮助，请输入 "help"
				if (strings.Contains(line, "Done (") && strings.Contains(line, ")! For help, type \"help\"")) ||
					(strings.Contains(line, "完成 (") && strings.Contains(line, ")! 如需帮助，请输入 \"help\"")) {
					serverMgr.status.Ready = true
					// 通过 Channel 通知
					select {
					case readyCh <- struct{}{}:
					default:
					}
					runtime.EventsEmit(serverMgr.ctx, "serverReady")
					runtime.EventsEmit(serverMgr.ctx, "serverStatus", serverMgr.status)
				}
			}
			serverMgr.mu.Unlock()

			// 发送日志事件
			runtime.EventsEmit(a.ctx, "serverLog", line)
		}
	}()

	// 等待进程退出
	go func() {
		cmd.Wait()
		serverMgr.mu.Lock()
		serverMgr.status.Running = false
		serverMgr.status.Ready = false
		serverMgr.status.PID = 0
		serverMgr.mu.Unlock()
		runtime.EventsEmit(a.ctx, "serverStatus", serverMgr.status)
	}()

	return nil
}

// WaitForServerReady 等待服务器启动完毕（供前端调用）
func (a *App) WaitForServerReady() error {
	serverMgr.mu.Lock()
	readyCh := serverMgr.readyCh
	if serverMgr.status.Ready {
		serverMgr.mu.Unlock()
		return nil
	}
	serverMgr.mu.Unlock()

	if readyCh == nil {
		return fmt.Errorf("服务器未在运行")
	}

	select {
	case <-readyCh:
		return nil
	case <-time.After(180 * time.Second):
		return fmt.Errorf("服务器启动超时（3分钟）")
	}
}

// StopServer 停止服务器
func (a *App) StopServer() error {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()

	if !serverMgr.status.Running || serverMgr.stdin == nil {
		return fmt.Errorf("服务器未在运行")
	}

	// 发送 stop 命令
	_, err := serverMgr.stdin.Write([]byte("stop\n"))
	if err != nil {
		// 强制终止
		if serverMgr.cmd != nil && serverMgr.cmd.Process != nil {
			serverMgr.cmd.Process.Kill()
		}
	}

	return nil
}

// SendServerCommand 向服务器发送命令
func (a *App) SendServerCommand(cmd string) error {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()

	if !serverMgr.status.Running || serverMgr.stdin == nil {
		return fmt.Errorf("服务器未在运行")
	}

	_, err := serverMgr.stdin.Write([]byte(cmd + "\n"))
	return err
}

// GetServerStatus 获取服务器状态
func (a *App) GetServerStatus() ServerStatus {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	return serverMgr.status
}

// GetServerLogs 获取服务器日志
func (a *App) GetServerLogs() []string {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	result := make([]string, len(serverMgr.logBuffer))
	copy(result, serverMgr.logBuffer)
	return result
}

// getServerConfig 读取服务器配置
func (a *App) getServerConfig(name string) (*ServerConfig, error) {
	serverDir := a.GetServerDir()
	configPath := filepath.Join(serverDir, name, "QGL", "config.json")

	// 也检查自定义目录
	data, err := os.ReadFile(configPath)
	if err != nil {
		// 尝试从服务器列表中查找
		list, listErr := a.GetServerList()
		if listErr != nil {
			return nil, fmt.Errorf("读取配置失败: %v", err)
		}
		for _, s := range list {
			if s.Name == name {
				return &s, nil
			}
		}
		return nil, fmt.Errorf("找不到服务器 %s", name)
	}

	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %v", err)
	}
	return &cfg, nil
}

// SetServerOnlineMode 设置服务器正版验证（需要重启）
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
