package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

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
