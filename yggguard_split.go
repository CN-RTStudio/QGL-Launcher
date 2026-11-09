package main

import (
	"strings"
)

// validateYggToken 校验外置 accessToken / clientToken：限长、禁控制字符与任何空白，
// 防止超长串耗尽存储 / 命令行，以及换行在下游拼接头时形成 HTTP 头注入。
// clientToken 允许为空（部分服务器不返回）。
func validateYggToken(token string, allowEmpty bool) string {
	if token == "" {
		if allowEmpty {
			return ypOK
		}
		return ypTokenBad
	}
	if len(token) > maxYggTokenLen {
		return ypTokenBad
	}
	for _, c := range token {
		if c <= 32 || c == 127 {
			return ypTokenBad
		}
	}
	return ypOK
}

// YggProfile 是通过校验、可安全落盘 / 用于启动的外置角色身份。
type YggProfile struct {
	Name string // 合法 Minecraft 角色名
	UUID string // 32 位小写十六进制
}

// pickYggProfile 从 authenticate / refresh 返回的角色列表里挑出第一个合法角色。
// selected 非空时优先用它；否则在 available 里顺序找第一个合法的。
// 全部不合法时返回 ok=false，调用方必须拒绝登录而不是使用畸形身份。
func pickYggProfile(selected *struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}, available []struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}) (YggProfile, bool) {
	try := func(id, name string) (YggProfile, bool) {
		if validateYggProfileName(name) != ypOK {
			return YggProfile{}, false
		}
		uuid, ok := canonicalYggProfileUUID(id)
		if !ok {
			return YggProfile{}, false
		}
		return YggProfile{Name: name, UUID: uuid}, true
	}
	if selected != nil {
		if p, ok := try(selected.ID, selected.Name); ok {
			return p, true
		}
	}
	for i := range available {
		if p, ok := try(available[i].ID, available[i].Name); ok {
			return p, true
		}
	}
	return YggProfile{}, false
}

// validateYggServerName 校验皮肤站自报的展示名，仅限长并去控制字符，
// 它只用于界面展示不参与落盘 / 命令行，但仍防止畸形字符串搞乱日志与渲染。
func validateYggServerName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if len(name) > maxYggServerNameLen {
		return "", false
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return "", false
		}
	}
	return name, true
}

// describeYggReject 把角色资料拒绝原因码转成中文说明。
func describeYggReject(why string) string {
	switch why {
	case ypNameEmpty:
		return "外置服务器返回的角色名为空"
	case ypNameLen:
		return "外置服务器返回的角色名长度不合法"
	case ypNameChar:
		return "外置服务器返回的角色名包含非法字符"
	case ypUUIDBad:
		return "外置服务器返回的角色 UUID 不是合法十六进制"
	case ypTokenBad:
		return "外置服务器返回的访问令牌不合法"
	default:
		return "外置登录数据未通过校验"
	}
}
