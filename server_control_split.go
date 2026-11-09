package main

import (
	"fmt"
	"path/filepath"
)

// getServerConfig 读取服务器配置
// 安全加固: 校验 name 不含路径遍历字符
// validateLoadedServerConfig 在信任磁盘上的 config.json 之前重新校验全部字段。
//
// 创建时的校验只挡得住前端正常流程；config.json 之后还可能被手工编辑、云盘同步、
// 旧版本写坏或被其他进程篡改。这里的字段（尤其 Version、ServerDir）随后会进入
// 文件路径拼接与 `java -jar <version>-server.jar`，属于代码执行面，因此加载时
// 必须像创建时一样逐项过白名单，任何越界 / 非法值都直接拒绝，绝不带病启动。
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
