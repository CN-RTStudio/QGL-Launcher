package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func (a *App) CreateServer(name, version string, port, maxMem, minMem int, onlineMode bool, customDir string) error {
	name = sanitizeServerName(name)
	if name == "" {
		return fmt.Errorf("服务器名称不能为空")
	}
	if err := sanitizePathComponent(version); err != nil {
		return fmt.Errorf("无效的版本号: %v", err)
	}
	if !isValidPort(port) {
		return fmt.Errorf("端口号必须在 %d-%d 之间", minPort, maxPort)
	}
	if !isValidMemory(maxMem) || !isValidMemory(minMem) {
		return fmt.Errorf("内存必须在 %d-%d MB 之间", minMemoryMB, maxMemoryMB)
	}
	if minMem > maxMem {
		return fmt.Errorf("最小内存不能大于最大内存")
	}

	// 端口占用预检：在创建目录 / 下载 JAR 之前就发现端口冲突，避免用户一路配置完、
	// 启动时才在服务端日志里看到绑定失败。探测为咨询性（存在 TOCTOU 窗口），最终
	// 仍以 JVM 实际绑定为准；不受支持的协议族不算冲突。
	if probe := IsTCPPortAvailable(port); !probe.Free {
		return fmt.Errorf("端口 %d 无法使用：%s", port, describePortProbeReason(probe.Reason))
	}

	serverDir := a.GetServerDir()
	var dir string
	if customDir != "" {
		// 必须是绝对路径：否则 isPathTraversal 内部的 filepath.Abs 会按进程当前
		// 工作目录解析相对路径，判定基准随启动方式漂移，可能被绕过。
		if !filepath.IsAbs(customDir) {
			return fmt.Errorf("自定义目录必须是绝对路径")
		}
		customDir = filepath.Clean(customDir)
		if isPathTraversal(serverDir, customDir) {
			return fmt.Errorf("自定义目录路径不安全")
		}
		dir = customDir
	} else {
		dir = filepath.Join(serverDir, name)
	}

	if info, statErr := os.Lstat(dir); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("服务器目录不能是符号链接")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "QGL", "config.json")); statErr == nil {
		return fmt.Errorf("目录 %s 已存在服务器配置，拒绝覆盖", dir)
	}

	if err := os.MkdirAll(dir, allowedDirPerm); err != nil {
		return fmt.Errorf("创建服务器目录失败: %v", err)
	}

	qglDir := filepath.Join(dir, "QGL")
	if err := os.MkdirAll(qglDir, allowedDirPerm); err != nil {
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
	// config.json 随后会进入 java -jar 执行路径，按敏感状态文件走原子私有写：
	// 防半截写、防预置符号链接写穿、强制 0600。
	if err := secureWritePrivateFile(filepath.Join(qglDir, "config.json"), cfgData); err != nil {
		return fmt.Errorf("保存配置失败: %v", err)
	}

	if err := a.downloadServerJar(version, dir); err != nil {
		return fmt.Errorf("下载服务器文件失败: %v", err)
	}

	eulaData := []byte("# By changing the setting below to TRUE you are indicating your agreement to our EULA (https://aka.ms/MinecraftEULA).\neula=true\n")
	if err := secureWriteFile(filepath.Join(dir, "eula.txt"), eulaData, allowedFilePerm); err != nil {
		return fmt.Errorf("创建 eula.txt 失败: %v", err)
	}

	// 初始 server.properties 走统一的安全读写器：键名 / 单行值 / motd 全部校验，
	// 原子写 .tmp 再 rename。旧实现 fmt.Sprintf 裸拼文本，motd 里的特殊语义字符
	// （前导空格、#、Tab、反斜杠等）没有经过 properties 值规则，存在配置注入不一致面。
	if err := writeInitialServerProperties(filepath.Join(dir, "server.properties"), port, onlineMode, name); err != nil {
		return fmt.Errorf("创建 server.properties 失败: %v", err)
	}

	return nil
}
