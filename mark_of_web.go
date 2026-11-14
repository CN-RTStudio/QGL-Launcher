package main

import (
	"errors"
	"fmt"
	"strings"
)

const (
	zoneIdentifierStream = ":Zone.Identifier"
	zoneIDInternet       = 3
	motwMaxURLLength     = 2048
)

var errMarkOfTheWebUnsupported = errors.New("当前平台不支持 Mark of the Web")

func sanitizeZoneURL(raw string) (string, error) {
	u := strings.TrimSpace(raw)
	if u == "" {
		return "", nil
	}
	if len(u) > motwMaxURLLength {
		return "", fmt.Errorf("URL 超过 %d 字符", motwMaxURLLength)
	}
	if strings.ContainsAny(u, "\r\n") {
		return "", errors.New("URL 含有非法换行符")
	}
	return u, nil
}

func buildZoneIdentifierBody(hostURL, referrerURL string) (string, error) {
	host, err := sanitizeZoneURL(hostURL)
	if err != nil {
		return "", fmt.Errorf("HostUrl 非法: %w", err)
	}
	referrer, err := sanitizeZoneURL(referrerURL)
	if err != nil {
		return "", fmt.Errorf("ReferrerUrl 非法: %w", err)
	}
	var b strings.Builder
	b.WriteString("[ZoneTransfer]\r\n")
	b.WriteString(fmt.Sprintf("ZoneId=%d\r\n", zoneIDInternet))
	if referrer != "" {
		b.WriteString("ReferrerUrl=" + referrer + "\r\n")
	}
	if host != "" {
		b.WriteString("HostUrl=" + host + "\r\n")
	}
	return b.String(), nil
}

// fileSupportsADS 判断路径所在位置能否承载 NTFS 备用数据流。
// 只做必要的廉价检查：文件存在且是普通文件（符号链接 / 特殊文件一律拒绝，
// 防止把 MOTW 写到链接目标上）。
