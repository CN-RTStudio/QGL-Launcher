package main

// configguard.go —— 写进用户配置文件（users/<name>/config.json）的外部输入收口内核。
//
// 威胁模型：
//
//	Wails 会把渲染层方法直接暴露给前端，SetThemeColor / SetSelectedVersion 的参数
//	完全来自渲染层，历史实现原样塞进 UserConfig 落盘：
//	  1. SetThemeColor 的 color 没有白名单。该值随后被前端读回当作 data-theme 属性、
//	     拼进选择器 / 样式键；写入畸形值（超长串、控制字符、</script> 一类内容）可做
//	     配置投毒：一旦配置被另一处未转义渲染，就形成存储型 XSS / 界面破坏；
//	  2. SetSelectedVersion 的 versionID 不只是展示字段——它随后会被拼进
//	     versions/<versionID>/... 路径（GetDefaultModModDir、隔离存档目录等）。虽然
//	     落盘本身用了 0600 原子写，但值里若带 "../"、反斜杠或保留设备名，会在后续路径
//	     拼接面产生路径穿越 / Windows 设备名问题。
//
//	这两个值都来自不可信的渲染层，必须在主进程侧做白名单 / 单段名校验，而不是相信
//	前端只传固定选项。一律“非法即拒绝并记审计”，不做静默替换。

import "strings"

const (
	// maxVersionIDLen 版本 ID 的单段长度上限。官方版本号（1.20.4、24w14a、
	// 1.20.4-pre1）与常见加载器版本名都远小于此，给到 128 留足第三方版本空间。
	maxVersionIDLen = 128
)

// 拒绝原因码：空串表示通过。
const (
	configRejectNone     = ""
	configRejectEmpty    = "empty"
	configRejectUnknown  = "unknown-value" // 主题色不在白名单
	configRejectLength   = "too-long"      // 版本 ID 超长
	configRejectUnsafeID = "unsafe-id"     // 版本 ID 含分隔符 / 控制字符 / 保留设备名等
)

// allowedThemeColors 是唯一允许落盘的主题色集合，必须与前端 themeColors 的 id 完全一致：
// blue / cyan / pink / purple / orange / yellow / green。
var allowedThemeColors = map[string]bool{
	"blue":   true,
	"cyan":   true,
	"pink":   true,
	"purple": true,
	"orange": true,
	"yellow": true,
	"green":  true,
}

// SafeThemeColor 校验主题色标识：去首尾空白后必须精确命中白名单，否则返回空串。
// 不做大小写归一，避免把 "CYAN" 之类的非预期值悄悄换写成另一个键。
func SafeThemeColor(color string) (string, string) {
	c := strings.TrimSpace(color)
	if c == "" {
		return "", configRejectEmpty
	}
	if !allowedThemeColors[c] {
		return "", configRejectUnknown
	}
	return c, configRejectNone
}

// SafeVersionID 校验选中版本 ID。该值会拼进 versions/<id> 路径，因此按“单段安全
// 路径名”处理：长度受限、不得含任何分隔符 / 控制字符 / 冒号、不得为 "."/".."、
// 不得是 Windows 保留设备名、首尾不能有点或空格（复用 pathguard 的 validateSafeSegment）。
func SafeVersionID(id string) (string, string) {
	v := strings.TrimSpace(id)
	if v == "" {
		// 空版本表示“尚未选择”，是 GetSelectedVersion 的合法默认态，允许清空。
		return "", configRejectNone
	}
	if len(v) > maxVersionIDLen {
		return "", configRejectLength
	}
	if !validateSafeSegment(v) {
		return "", configRejectUnsafeID
	}
	return v, configRejectNone
}
