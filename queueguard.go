package main

// queueguard：下载队列审计。
//
// 场景：版本 json / 镜像索引 / 实例升级会构造批量下载计划（URL + 落盘路径 +
// 期望哈希）。恶意清单可让启动器：批量请求内网地址（SSRF）、把下载目标写到
// 任意相对路径、声明超大总量把磁盘拖垮、或条目数爆炸拖垮调度。本模块对一
// 个下载计划做纯函数审计：
//   - 每条 URL：https/http 且 host 通过白名单（默认允许 Mojang/BMCLAPI/
//     Fabric/Forge 等常见域，可注入），无用户信息（user:pass@）与端口白名单；
//   - 落盘路径：相对 targetRoot 之下，无穿越 / 盘符 / 反斜杠 / 控制字符；
//   - 总条目数与总字节数上限；期望哈希 40/64 位 hex 或空（由调用方决定）；
//   - 输出净化后的计划供下游执行。

import (
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

// QueueLimits 下载队列审计的量化边界。
type QueueLimits struct {
	MaxEntries   int
	MaxTotalSize int64
	MaxNameLen   int
	AllowedHosts []string // 空 = 默认白名单
	AllowedPorts map[string]bool
}

func defaultQueueLimits() QueueLimits {
	return QueueLimits{
		MaxEntries:   100000,
		MaxTotalSize: 64 << 30, // 64 GiB 计划总量上限
		MaxNameLen:   512,
		AllowedHosts: []string{
			"launcher.mojang.com", "piston-meta.mojang.com", "resources.download.minecraft.net",
			"libraries.minecraft.net", "bmclapi2.bangbang93.com", "meta.fabricmc.net",
			"maven.fabricmc.net", "maven.minecraftforge.net", "files.minecraftforge.net",
			"maven.neoforged.net", "api.modrinth.com", "cdn.modrinth.com", "optifine.net",
			"authserver.mojang.com", "sessionserver.mojang.com", "api.minecraftservices.com",
			"api.github.com", "codeload.github.com",
		},
		AllowedPorts: map[string]bool{"80": true, "443": true, "8080": true, "8443": true},
	}
}

type queueItem struct {
	URL  string
	Dest string // 相对路径
	Hash string
	Size int64
}

type queueVerdict struct {
	OK     bool
	Reason string
	Clean  []queueItem
	Total  int64
}

// hostAllowedQ 检查 host（含端口）是否在允许集合内。
// 旧实现用 LastIndex(host, ":") 剥端口：IPv6 字面量 `[::1]:443` 被切成
// 主机 "[::1" + 端口 "443" 之后仍拼不回去，裸 IPv6 `2001:db8::1` 更会被当成
// 端口 "1"；反过来无端口的主机名又直接跳过端口白名单，8443 之类的放行端口
// 等于从未生效。这里改成结构化拆分（IPv6 方括号 / 单冒号 / 裸 IPv6 分别处理），
// 端口缺省按 https 443 计。
func hostAllowedQ(host string, lim QueueLimits) bool {
	name, port, ok := splitQueueAuthority(host)
	if !ok {
		return false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return false
	}
	if port == "" {
		port = "443"
	} else if !isDigits(port) {
		return false
	}
	if len(lim.AllowedPorts) > 0 && !lim.AllowedPorts[port] {
		return false
	}
	for _, allowed := range lim.AllowedHosts {
		a := strings.ToLower(strings.TrimSuffix(allowed, "."))
		if a == "" {
			continue
		}
		if name == a || strings.HasSuffix(name, "."+a) {
			return true
		}
	}
	return false
}

// splitQueueAuthority 把 authority 拆成「主机 + 端口」。
// 返回值 ok=false 表示形态非法（空主机、多冒号又不是 IPv6、方括号不闭合、
// 混进路径/查询/凭据分隔符），调用方应直接拒绝而不是猜一个主机出来。
func splitQueueAuthority(host string) (string, string, bool) {
	h := strings.TrimSpace(host)
	if h == "" {
		return "", "", false
	}
	if strings.ContainsAny(h, " \t\r\n/") || strings.ContainsAny(h, "/@?#\\") {
		return "", "", false
	}
	if strings.HasPrefix(h, "[") {
		end := strings.Index(h, "]")
		if end < 0 {
			return "", "", false
		}
		name := h[:end+1]
		rest := h[end+1:]
		if rest == "" {
			return name, "", true
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", false
		}
		return name, rest[1:], true
	}
	if strings.Count(h, ":") == 0 {
		return h, "", true
	}
	if net.ParseIP(h) != nil {
		return h, "", true
	}
	if strings.Count(h, ":") == 1 {
		i := strings.Index(h, ":")
		name := h[:i]
		port := h[i+1:]
		if name == "" || port == "" {
			return "", "", false
		}
		return name, port, true
	}
	return "", "", false
}

// validateQueueURL 校验单条下载 URL。
func validateQueueURL(raw string, lim QueueLimits) string {
	if raw == "" {
		return "url-parse-fail"
	}
	if len(raw) > 4096 {
		return "url-too-long"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "url-parse-fail"
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "url-scheme"
	}
	if u.User != nil {
		return "url-userinfo"
	}
	if u.Opaque != "" {
		return "url-opaque"
	}
	if u.Host == "" || u.Hostname() == "" {
		return "url-no-host"
	}
	// 百分号编码主机（`%31%32%37.0.0.1`）在部分解析器上会还原成内网 IP，
	// 白名单比对的是编码后的字符串，等于把真正的目标藏起来；IPv6 作用域
	// 写法 `[fe80::1%25eth0]` 同样落在这里，一律拒绝。
	if strings.Contains(u.Host, "%") {
		return "url-host-encoded"
	}
	if !hostAllowedQ(u.Host, lim) {
		return "url-host:" + strings.ToLower(u.Host)
	}
	return ""
}

// validateQueueDest 校验落盘相对路径。
func validateQueueDest(dest string, lim QueueLimits) string {
	if dest == "" {
		return "dest-empty"
	}
	if len(dest) > lim.MaxNameLen {
		return "dest-too-long"
	}
	if strings.HasPrefix(dest, "/") || (len(dest) > 1 && dest[1] == ':') {
		return "dest-absolute"
	}
	if hasControlCharStr(dest) {
		return "dest-control-char"
	}
	if strings.Contains(dest, "\\") {
		return "dest-backslash"
	}
	if strings.Contains(dest, "..") {
		return "dest-dotdot"
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(dest)))
	if clean == "" || clean == "." || strings.HasPrefix(clean, "../") {
		return "dest-bad-clean"
	}
	return ""
}

// validateQueueHash 校验期望哈希（40 位 sha1 或 64 位 sha256，可空）。
func validateQueueHash(h string) string {
	if h == "" {
		return ""
	}
	if len(h) == 40 || len(h) == 64 {
		for _, c := range h {
			if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
				return "hash-illegal"
			}
		}
		return ""
	}
	return "hash-length"
}

// AuditDownloadQueue 审计整个下载计划。
func AuditDownloadQueue(items []queueItem, lim QueueLimits) queueVerdict {
	if lim.MaxEntries == 0 {
		lim = defaultQueueLimits()
	}
	vd := queueVerdict{OK: true}
	if len(items) > lim.MaxEntries {
		vd.OK = false
		vd.Reason = "queue-overflow"
		return vd
	}
	clean := make([]queueItem, 0, len(items))
	for i, it := range items {
		if r := validateQueueURL(it.URL, lim); r != "" {
			vd.OK = false
			vd.Reason = "item:" + itoaSafe(i) + ":url:" + r
			return vd
		}
		if r := validateQueueDest(it.Dest, lim); r != "" {
			vd.OK = false
			vd.Reason = "item:" + itoaSafe(i) + ":dest:" + r
			return vd
		}
		if r := validateQueueHash(it.Hash); r != "" {
			vd.OK = false
			vd.Reason = "item:" + itoaSafe(i) + ":hash:" + r
			return vd
		}
		if it.Size < 0 {
			vd.OK = false
			vd.Reason = "item:" + itoaSafe(i) + ":size-negative"
			return vd
		}
		vd.Total += it.Size
		if vd.Total > lim.MaxTotalSize {
			vd.OK = false
			vd.Reason = "total-size-overflow"
			return vd
		}
		clean = append(clean, it)
	}
	vd.Clean = clean
	return vd
}

// SummarizeQueueVerdict 压成一行。
func SummarizeQueueVerdict(vd queueVerdict) string {
	if vd.OK {
		return "queue ok entries=" + itoaSafe(len(vd.Clean)) + " totalMB=" + itoaSafe64(vd.Total/(1<<20))
	}
	return "queue bad " + vd.Reason
}

// itoaSafe64 int64 转十进制字符串（无符号越界）。
func itoaSafe64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
