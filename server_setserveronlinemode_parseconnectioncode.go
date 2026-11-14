package main

import (
	"fmt"
	"strconv"
	"strings"

)

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
