package main

import (
	"math/big"
	"net"
	"net/url"
)

// UMFS (Ultra Mersenne Fractal Sponge) — 与 bool-hybrid-array core.py 对齐。
// M = 2^2281 - 1（梅森素数），十阶模幂 + 海绵结构。
var (
	umfsM   = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 2281), big.NewInt(1))
	umfsE1  = big.NewInt(11)
	umfsE2  = big.NewInt(13)
	umfsE3  = big.NewInt(17)
	umfsE4  = big.NewInt(19)
	umfsE5  = big.NewInt(23)
	umfsE6  = big.NewInt(29)
	umfsE7  = big.NewInt(31)
	umfsE8  = big.NewInt(37)
	umfsE9  = big.NewInt(41)
	umfsE10 = big.NewInt(43)
	umfsIVR = big.NewInt(0x2957A2F168CC3509)
	umfsIVC = big.NewInt(0x71D39E40BB72A61F)
	umfsC1  = big.NewInt(0x19260817)
	umfsC2  = big.NewInt(0x114514)
	umfsC3  = big.NewInt(0xABCDEF)
	umfsC4  = big.NewInt(0x233333)
	umfsC5  = big.NewInt(0x666666)
	umfsC6  = big.NewInt(0x123456789)
	umfs210 = big.NewInt(210)
	umfs7   = big.NewInt(7)
	umfs3   = big.NewInt(3)
)

const umfsBlockSize = 8

// maxRedirects 单次请求最多跟 5 次跳转，超过就报错。
// 防止 CDN 被劫持后用无限跳转拖死启动。
const maxRedirects = 5

// isPrivateDest 报告 URL 指向的主机是不是内网/回环/链路本地地址。
// 启动器只该访问公网镜像和 Mojang，不应该被诱导去读 169.254.169.254
// （云元数据）或 127.0.0.1:本地端口。
func isPrivateDest(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	host := u.Hostname()
	if host == "" {
		return true
	}
	if isLoopbackHostName(host) {
		return true
	}
	// 用更宽的 IP 字面量解析器，连十六进制/八进制/扁平整数/IPv4-mapped
	// IPv6 等非规范写法一并在字符串态识别，防止绕过内网拦截。
	if ip, ok := parseDestIP(host); ok {
		return isBlockedIP(ip)
	}
	// 没解析成 IP 字面量的（域名），交给 DNS，不在这里拦；
	// 真正解析到内网的边缘情况由 net.Dialer 侧再兜一次。
	return false
}

// isBlockedIP 报告 IP 是否属于不该被启动器主动连出的地址段。判定表统一收敛到
// ipparse.go 的 isNonPublicIP，与浏览器打开 / 短链 / 重定向共用同一份最严策略，
// 覆盖回环、RFC1918 私网、CGNAT、链路本地（含云元数据 169.254.169.254）、未指定、
// 0.0.0.0/8 “本网络”段，以及此前漏掉的整段 224/4 多播（如 SSDP 239.255.255.250）
// 与 240/4 保留段（含 255.255.255.255 有限广播）。
func isBlockedIP(ip net.IP) bool {
	return isNonPublicIP(ip)
}
