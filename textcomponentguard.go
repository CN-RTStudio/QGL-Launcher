package main

// textcomponentguard.go —— Minecraft 聊天 TextComponent 树校验。
//
// 服务端/模组发来的聊天组件里可以带 clickEvent {open_url|run_command|suggest_command}
// 和 hoverEvent。run_command 一旦被用户误点就会在客户端执行 `/me`、`/tell` 之类命令；
// open_url 可被伪装成钓鱼链接。这里把组件树做一次纯函数收敛：
//
//   - 限制嵌套深度，防止 extra 套娃炸渲染；
//   - open_url 只接受 http/https，挡 data:/javascript:/file:；
//   - run_command 只允许白名单里的低危动作，其余降级；
//   - 文本节点拒绝控制字符。
//
// 不做渲染，只决定“这个组件能不能安全显示给玩家”。

import (
	"encoding/json"
	"fmt"
	"strings"
)

const maxTextComponentDepth = 16

// 允许 run_command 直接触发的白名单前缀（低频、无副作用）。
var allowedRunPrefixes = []string{"/help", "/list", "/? "}

// TextComponent 是 MC 富文本组件的最小结构。
type TextComponent struct {
	Text       string                 `json:"text"`
	Translate  string                 `json:"translate"`
	Extra      []json.RawMessage      `json:"extra"`
	ClickEvent map[string]interface{} `json:"clickEvent"`
	HoverEvent map[string]interface{} `json:"hoverEvent"`
}

// SanitizeTextComponent 校验并返回一个安全标记；问题计入 reasons。
func SanitizeTextComponent(raw []byte) (safe bool, reasons []string) {
	var root TextComponent
	if err := json.Unmarshal(raw, &root); err != nil {
		return false, []string{"malformed-json"}
	}
	reasons = walkComponent(&root, 0)
	return len(reasons) == 0, reasons
}

func walkComponent(c *TextComponent, depth int) []string {
	var out []string
	if depth > maxTextComponentDepth {
		return []string{"too-deep"}
	}
	if strings.ContainsAny(c.Text, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f") {
		out = append(out, "control-chars")
	}
	if c.ClickEvent != nil {
		if r := checkClick(c.ClickEvent); r != "" {
			out = append(out, r)
		}
	}
	for _, ex := range c.Extra {
		var child TextComponent
		if err := json.Unmarshal(ex, &child); err != nil {
			out = append(out, "malformed-extra")
			continue
		}
		out = append(out, walkComponent(&child, depth+1)...)
	}
	return out
}

func checkClick(ev map[string]interface{}) string {
	action, _ := ev["action"].(string)
	value, _ := ev["value"].(string)
	switch action {
	case "open_url":
		v := strings.ToLower(strings.TrimSpace(value))
		if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
			return "click-bad-url-scheme"
		}
	case "run_command":
		if !isAllowedRun(value) {
			return "click-run-blocked"
		}
	case "suggest_command":
		// 建议命令不直接执行，放行。
		return ""
	case "change_page", "copy_to_clipboard":
		// 翻书/复制相对安全。
		return ""
	default:
		return "click-unknown-action"
	}
	return ""
}

func isAllowedRun(cmd string) bool {
	trim := strings.TrimSpace(cmd)
	for _, p := range allowedRunPrefixes {
		if strings.HasPrefix(trim, p) {
			return true
		}
	}
	return false
}

// ValidateChatJSON 是便捷入口，返回错误文案。
func ValidateChatJSON(raw []byte) error {
	safe, reasons := SanitizeTextComponent(raw)
	if !safe {
		return fmt.Errorf("unsafe chat component: %s", strings.Join(reasons, ","))
	}
	return nil
}
