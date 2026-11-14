package main

import (
	"fmt"
)

func gameArgHasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
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
