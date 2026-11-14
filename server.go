package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
