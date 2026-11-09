package main

import (
	"strings"
)

// userDirVariants 生成用户名目录的常见写法（正/反斜杠、引号包裹、前加
// Windows 盘符与 Users 段）。
func userDirVariants(username string) []string {
	variants := []string{
		`Users\` + username,
		`Users/` + username,
		`\Users\` + username,
		`/Users/` + username,
		`"C:\Users\` + username + `"`,
		`C:\Users\` + username,
		`c:\users\` + strings.ToLower(username),
	}
	seen := make(map[string]bool, len(variants))
	var out []string
	for _, v := range variants {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// replaceDirCI 大小写不敏感地替换目录路径及其带尾分隔符变体。
func replaceDirCI(text, dir, placeholder string) string {
	dir = strings.TrimRight(strings.TrimSpace(dir), `\/`)
	if dir == "" {
		return text
	}
	variants := []string{dir, strings.ToLower(dir), strings.ToUpper(dir)}
	for _, v := range variants {
		// 正斜杠变体与反斜杠变体都要覆盖。
		bs := strings.ReplaceAll(v, `/`, `\`)
		fs := strings.ReplaceAll(v, `\`, `/`)
		text = strings.ReplaceAll(text, bs, placeholder)
		text = strings.ReplaceAll(text, fs, placeholder)
		// 尾分隔符变体（目录后跟 \ 或 /）。
		text = strings.ReplaceAll(text, bs+`\`, placeholder+`\`)
		text = strings.ReplaceAll(text, fs+`/`, placeholder+`/`)
	}
	return text
}

// crashTextPreview 生成崩溃文本的脱敏预览（用于审计事件 detail，限长）。
func crashTextPreview(text string, maxLen int) string {
	t := strings.TrimSpace(text)
	if len(t) > maxLen {
		t = t[:maxLen] + "..."
	}
	return t
}

// currentUsername 返回当前登录用户名（供脱敏用；未登录返回空）。
func (a *App) currentUsername() string {
	if u, err := a.GetCurrentUser(); err == nil {
		return u.Username
	}
	return ""
}
