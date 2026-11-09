package main

// yggguard.go —— Yggdrasil 外置登录服务器返回数据的收口内核。
//
// 威胁模型：
//   用户可以在启动器里配置任意外置登录（Yggdrasil / authlib-injector）服务器地址，
//   其中还允许回环 / 私网的自建皮肤站。这些服务器返回的 authenticate / refresh JSON
//   （selectedProfile / availableProfiles / accessToken）完全不受 Mojang 约束，属于
//   “用户主动连接、但内容仍不可信”的边界。历史代码把服务器给的 name / id 原样写进：
//     - 本地账号文件名（GetExternalAuthData 以 username 落盘）；
//     - 游戏启动命令行参数（--username ${auth_player_name}）；
//     - 玩家 UUID（拼进 authlib-injector prefetched、游戏会话）。
//   若恶意 / 被篡改的皮肤站返回 name = "../../x"、含空格与引号的名字，或非 hex 的 UUID，
//   就可能造成账号文件路径穿越、JVM 参数注入、会话身份畸形。令牌字符串若含换行还可能在
//   将来被拼进 HTTP 头时形成头注入。
//
// 本内核把“服务器返回的身份字段能不能用”收敛成纯函数：角色名限定 Minecraft 合法字符集、
// UUID 归一为 32 位小写十六进制、令牌限长且禁控制字符 / 空白。纯函数便于单测。

import "strings"

const (
	// maxYggProfileNameLen Minecraft 角色名上限（历史上为 16）。
	maxYggProfileNameLen = 16
	// minYggProfileNameLen Minecraft 角色名下限。
	minYggProfileNameLen = 1
	// maxYggTokenLen 外置 accessToken / clientToken 的长度上限，挡住超长串灌入加密存储与命令行。
	maxYggTokenLen = 4096
	// maxYggServerNameLen 皮肤站自报名称（meta.serverName）长度上限。
	maxYggServerNameLen = 128
)

// 角色资料拒绝原因码。
const (
	ypOK        = ""
	ypNameEmpty = "ygg-name-empty"
	ypNameLen   = "ygg-name-length"
	ypNameChar  = "ygg-name-charset"
	ypUUIDBad   = "ygg-uuid-bad"
	ypTokenBad  = "ygg-token-bad"
)

// validateYggProfileName 校验外置服务器返回的角色名。
// Minecraft 合法角色名只允许字母、数字、下划线；显式拒绝路径分隔符、空白、控制字符与点。
func validateYggProfileName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ypNameEmpty
	}
	if len(name) < minYggProfileNameLen || len(name) > maxYggProfileNameLen {
		return ypNameLen
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z') &&
			!(c >= 'A' && c <= 'Z') &&
			!(c >= '0' && c <= '9') &&
			c != '_' {
			return ypNameChar
		}
	}
	return ypOK
}

// canonicalYggProfileUUID 校验并归一角色 UUID。
// 接受 32 位十六进制（无连字符）或 8-4-4-4-12 带连字符两种形式，
// 统一返回 32 位小写十六进制；非法返回 ok=false。
func canonicalYggProfileUUID(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) != 5 ||
			len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
			len(parts[3]) != 4 || len(parts[4]) != 12 {
			return "", false
		}
		s = strings.Join(parts, "")
	}
	if len(s) != 32 {
		return "", false
	}
	for _, c := range s {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return "", false
		}
	}
	return strings.ToLower(s), true
}

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
