package main

import (
	"fmt"
	"strconv"
	"strings"

)

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
