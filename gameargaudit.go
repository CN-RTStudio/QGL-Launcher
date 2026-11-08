package main

import (
	"fmt"
	"strings"
)

// gameargaudit.go —— 游戏“客户端参数（game args）”最终值审计。
//
// 威胁模型：
//   传给 Minecraft 主类（net.minecraft.client.main.Main）的参数里，有一组是“启动器
//   保留参数”，它们承载会话与寻址：--username / --uuid / --accessToken / --server /
//   --port / --gameDir / --assetsDir / --assetIndex / --version / --width / --height 等。
//   正常情况下这些只能由启动器用本地可信数据（账号、安装目录）生成。
//
//   但现代版本 JSON 的 arguments.game 是“外部数据”（Mojang / Forge / Fabric / 第三方
//   整合包都能下发），其中的字符串经 resolveGameArg 展开成独立 argv。resolveGameArg 已
//   解决了“一个值里夹空格劈成多条”的 token 注入，却不会阻止一条“本身就合法成条”的
//   恶意游戏参数，例如被篡改的整合包 JSON 里塞入：
//       --server  evil-relay.example
//       --port    25565
//       --accessToken <攻击者受控值>
//       --quickPlayMultiplayer evil-relay
//   效果：游戏启动后被静默导向攻击者的服务器（会话令牌随后发往对方），或覆盖会话
//   寻址。这类参数只能出现在“启动器生成段”，绝不能由版本 JSON 提供。
//
//   本模块在 gameArgs 完全展开后做一次最终验收：
//     1) 拒绝外部段携带任何启动器保留 flag（critical，整条剔除并留痕）；
//     2) 值不允许 NUL/CR/LF/其它控制字符（CreateProcess 与下游解析歧义）；
//     3) 单值长度、总条数有界，拦住畸形/放大 JSON；
//   判定为纯字符串，不触碰文件系统。调用方把“可信启动器参数”与“外部游戏参数”分开
//   传入：可信段跳过保留名冲突检查，外部段必须检查。

const (
	maxGameArgValueBytes = 32 * 1024
	maxExternalGameArgs  = 512
)

// 会话劫持类游戏参数：这些 flag “绝不会”出现在官方/加载器的版本 JSON 里——它们只在
// “快速加入联机”或“自定义代理”时由启动器按用户操作临时附加。若外部版本 JSON 自带，
// 唯一目的就是把游戏会话导向攻击者的服务器/代理（随后令牌发往对方）。
//
// 注意：--username/--uuid/--accessToken/--gameDir/--assetsDir/--version/--width/--height
// 等“占位参数”官方版本 JSON 本来就会带（值是 ${auth_access_token} 这类占位符，由
// resolveGameArg 展开），因此不能在此拦截；对它们的“值是否被换成非占位字面量”的防护
// 必须在替换发生前对原始 JSON 做（见 resolveGameArg 上游），本模块只负责零误伤的劫持
// flag 收口与通用的控制字符/长度/条数边界。
var hijackGameArgFlags = map[string]struct{}{
	"server":                 {},
	"port":                   {},
	"quickplaymultiplayer":   {},
	"quickplaysingleplayer":  {},
	"quickplayrealms":        {},
	"proxyhost":              {},
	"proxyport":              {},
	"proxyuser":              {},
	"proxypass":              {},
	"proxypass_":             {},
	"initialdir":             {}, // 等价于改 gameDir 的第三方 client 约定
}

// GameArgAudit 聚合游戏参数审计结论。
type GameArgAudit struct {
	Findings []LaunchFinding `json:"findings"`
	Critical int             `json:"critical"`
	Warns    int             `json:"warns"`
	// SafeExternal 仅保留来自外部段、且通过全部检查的参数（保持顺序）。
	SafeExternal []string `json:"safeExternal"`
	Rejected     int      `json:"rejected"`
}

func (g *GameArgAudit) add(code, severity, field, detail string) {
	g.Findings = append(g.Findings, LaunchFinding{Code: code, Severity: severity, Field: field, Detail: detail})
	switch severity {
	case launchSeverityCritical:
		g.Critical++
	case launchSeverityWarn:
		g.Warns++
	}
}

// HasCritical 报告是否存在必须中止启动的结论。
func (g *GameArgAudit) HasCritical() bool { return g.Critical > 0 }

// FirstCriticalCode 返回首个 critical 代码。
func (g *GameArgAudit) FirstCriticalCode() string {
	for _, f := range g.Findings {
		if f.Severity == launchSeverityCritical {
			return f.Code
		}
	}
	return ""
}

// normalizeGameFlag 把一个 token 规整成“不带前导连字符的小写 flag 名”。
// "--server" / "-server" / "--server=..." -> "server"；不是 flag（不以 - 开头，或
// 单纯 "-"）返回 ok=false。operandSeparated=true 表示形如 "--server value"（下一条是
// 值）；等于 false 表示自携带值 "--server=x" 或裸 flag。
func normalizeGameFlag(token string) (name string, separated bool, ok bool) {
	t := token
	if len(t) < 2 || t[0] != '-' {
		return "", false, false
	}
	t = strings.TrimLeft(t, "-")
	if t == "" {
		return "", false, false
	}
	// 形如 -Dxxx / -X 这类 JVM 形态不应出现在游戏段，交给调用方按值记录；这里只识别
	// 标准的 --flag / --flag=value。
	if idx := strings.IndexByte(t, '='); idx >= 0 {
		return strings.ToLower(t[:idx]), false, true
	}
	return strings.ToLower(t), true, true
}

// gameFindingsContainCode 报告一组 finding 中是否含指定 code（生产代码可用）。
func gameFindingsContainCode(fs []LaunchFinding, code string) bool {
	for _, f := range fs {
		if f.Code == code {
			return true
		}
	}
	return false
}

func gameArgHasControlByte(s string) bool {	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0 || c == '\r' || c == '\n' || c == '\t' || c < 0x20 {
			return true
		}
	}
	return false
}

// AuditExternalGameArgs 审计“来自版本 JSON 的外部游戏参数”。external 是 resolveGameArg
// 展开后的 token 流；保留名 flag 与其可能的操作数会一并剔除。
func AuditExternalGameArgs(external []string) *GameArgAudit {
	g := &GameArgAudit{}
	if len(external) > maxExternalGameArgs {
		g.add("ga-too-many", launchSeverityCritical, "gameArgs",
			fmt.Sprintf("外部游戏参数 %d 条超过上限 %d", len(external), maxExternalGameArgs))
	}

	skipOperand := false
	for i := 0; i < len(external); i++ {
		arg := external[i]
		field := fmt.Sprintf("gameArg[%d]", i)

		if skipOperand {
			skipOperand = false
			// 这是被剔除保留 flag 的操作数（攻击载荷，如服务器地址/令牌），绝不能作为
			// 普通游戏参数保留，整条丢弃；顺带记录其形态（控制符/超长）。
			g.Rejected++
			if gameArgHasControlByte(arg) {
				g.add("ga-control", launchSeverityCritical, field, "保留参数操作数含控制字符")
			} else if len(arg) > maxGameArgValueBytes {
				g.add("ga-long", launchSeverityCritical, field, "保留参数操作数过长")
			}
			continue
		}

		if len(arg) > maxGameArgValueBytes {
			g.add("ga-long", launchSeverityCritical, field, "游戏参数值过长")
			g.Rejected++
			continue
		}
		if gameArgHasControlByte(arg) {
			g.add("ga-control", launchSeverityCritical, field, "游戏参数值含控制字符/NUL/换行")
			g.Rejected++
			continue
		}

		if name, separated, isFlag := normalizeGameFlag(arg); isFlag {
			if _, hijack := hijackGameArgFlags[name]; hijack {
				g.add("ga-hijack-flag", launchSeverityCritical, field,
					"外部版本 JSON 携带会话劫持参数: --"+name)
				g.Rejected++
				// 分离式写法时，下一条是其值（攻击载荷，如服务器地址/端口），一并丢弃。
				if separated && i+1 < len(external) {
					skipOperand = true
				}
				continue
			}
			// 非劫持 flag 正常保留（官方占位参数与 Minecraft/模组的业务开关）。
		}

		g.SafeExternal = append(g.SafeExternal, arg)
	}
	return g
}

// AuditReservedGameValues 校验“启动器自己生成的保留参数值”是否干净（无控制字符、长度
// 有界）。它不拒绝保留名（这些值本就该出现），只保证值本身不可被注入。
// values 形如 {"--server": host, "--port": port, ...}，空值跳过。
func AuditReservedGameValues(values map[string]string) *GameArgAudit {
	g := &GameArgAudit{}
	for flag, v := range values {
		if v == "" {
			continue
		}
		field := "reserved:" + flag
		if len(v) > maxGameArgValueBytes {
			g.add("ga-reserved-long", launchSeverityCritical, field, "启动器保留参数值过长: "+flag)
		}
		if gameArgHasControlByte(v) {
			g.add("ga-reserved-control", launchSeverityCritical, field, "启动器保留参数值含控制字符: "+flag)
		}
	}
	return g
}
