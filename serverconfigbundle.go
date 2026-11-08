package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	serverConfigBundleVersion  = 1
	serverConfigBundleMaxBytes = 8 << 10
	serverConfigBundleNameRune = 64
	serverConfigBundleStampMax = int64(1) << 40
)

type ServerConfigBundle struct {
	Version    int    `json:"version"`
	Name       string `json:"name"`
	MCVersion  string `json:"mcVersion"`
	Port       int    `json:"port"`
	MinMemory  int    `json:"minMemory"`
	MaxMemory  int    `json:"maxMemory"`
	OnlineMode bool   `json:"onlineMode"`
	CreatedAt  int64  `json:"createdAt"`
}

func (bundle ServerConfigBundle) Describe() string {
	return fmt.Sprintf("%s（%s，端口 %d，内存 %d-%d MB，正版校验 %v）",
		bundle.Name, bundle.MCVersion, bundle.Port, bundle.MinMemory, bundle.MaxMemory, bundle.OnlineMode)
}

func normalizeServerConfigBundle(bundle ServerConfigBundle, now time.Time) (ServerConfigBundle, error) {
	out := bundle
	out.Version = serverConfigBundleVersion

	name := strings.TrimSpace(out.Name)
	if name == "" {
		return out, fmt.Errorf("服务器名称不能为空")
	}
	if len([]rune(name)) > serverConfigBundleNameRune {
		return out, fmt.Errorf("服务器名称超过 %d 个字符", serverConfigBundleNameRune)
	}
	if clean := SanitizeServerName(name, ServerListLimits{}); clean == "" {
		return out, fmt.Errorf("服务器名称包含非法字符")
	}
	out.Name = name

	if err := sanitizePathComponent(out.MCVersion); err != nil {
		return out, fmt.Errorf("无效的版本号: %v", err)
	}
	if !isValidPort(out.Port) {
		return out, fmt.Errorf("端口号必须在 %d-%d 之间", minPort, maxPort)
	}
	if !isValidMemory(out.MinMemory) || !isValidMemory(out.MaxMemory) {
		return out, fmt.Errorf("内存必须在 %d-%d MB 之间", minMemoryMB, maxMemoryMB)
	}
	if out.MinMemory > out.MaxMemory {
		return out, fmt.Errorf("最小内存不能大于最大内存")
	}

	if out.CreatedAt <= 0 || out.CreatedAt > serverConfigBundleStampMax {
		out.CreatedAt = now.UnixMilli()
	}
	return out, nil
}

func MarshalServerConfigBundle(cfg ServerConfig, now time.Time) ([]byte, error) {
	bundle, err := normalizeServerConfigBundle(ServerConfigBundle{
		Name:       cfg.Name,
		MCVersion:  cfg.Version,
		Port:       cfg.Port,
		MinMemory:  cfg.MinMemory,
		MaxMemory:  cfg.MaxMemory,
		OnlineMode: cfg.OnlineMode,
		CreatedAt:  now.UnixMilli(),
	}, now)
	if err != nil {
		return nil, err
	}
	payload, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化服务器配置失败: %v", err)
	}
	if len(payload) > serverConfigBundleMaxBytes {
		return nil, fmt.Errorf("服务器配置超过 %d 字节上限", serverConfigBundleMaxBytes)
	}
	return payload, nil
}

func ParseServerConfigBundle(data []byte) (ServerConfigBundle, error) {
	var bundle ServerConfigBundle
	if len(data) == 0 {
		return bundle, fmt.Errorf("配置内容为空")
	}
	if len(data) > serverConfigBundleMaxBytes {
		return bundle, fmt.Errorf("配置超过 %d 字节上限", serverConfigBundleMaxBytes)
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return bundle, fmt.Errorf("配置不是合法 JSON: %v", err)
	}
	if bundle.Version != serverConfigBundleVersion {
		return bundle, fmt.Errorf("不支持的配置版本 %d", bundle.Version)
	}
	out, err := normalizeServerConfigBundle(bundle, time.Now())
	if err != nil {
		return bundle, err
	}
	return out, nil
}

func (a *App) ExportServerConfig(name string) (string, error) {
	if err := sanitizePathComponent(name); err != nil {
		return "", fmt.Errorf("无效的服务器名称")
	}
	cfg, err := a.getServerConfig(name)
	if err != nil {
		return "", err
	}
	payload, err := MarshalServerConfigBundle(*cfg, time.Now())
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func (a *App) ParseImportedServerConfig(text string) (ServerConfigBundle, error) {
	return ParseServerConfigBundle([]byte(text))
}
