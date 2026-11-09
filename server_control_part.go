package main

import (
	"encoding/json"
	"fmt"
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
