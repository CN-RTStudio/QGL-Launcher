package main

// cmdlineleakguard.go —— 启动命令行“凭据经参数外泄”检测内核（纯函数）。
//
// 真实威胁：Mojang/authlib 的 accessToken、clientToken、会话 id 一旦作为
// -Dfoo=xxx 或裸参数拼进 java 命令行，任何能列进程的同机用户（任务管理器 /
// ps）都能读到这串令牌，拿去冒用账号。日志里脱敏（secretleakguard）管不到
// /proc/<pid>/cmdline 这个面。这里在真正 exec 前扫一遍参数表，命中即判定为泄露，
// 由上层决定是剥掉该参数还是直接拒绝启动。
//
// 只做扫描与分级，不修改命令行本身，避免误删合法参数。

import (
	"strings"
)

// cmdlineLeakKind 描述一条泄露类型。
type cmdlineLeakKind string

const (
	leakAccessToken   cmdlineLeakKind = "access-token"
	leakClientToken   cmdlineLeakKind = "client-token"
	leakSessionID     cmdlineLeakKind = "session-id"
	leakPasswordKV    cmdlineLeakKind = "password-kv"
	leakAuthorization cmdlineLeakKind = "authorization-header"
)

// CmdlineLeak 是一条命中：第几个参数、命中的键名、类型。
type CmdlineLeak struct {
	Index int
	Key   string
	Kind  cmdlineLeakKind
}

// leakKeyPattern 是已知会承载凭据的参数键（小写匹配）。值里只看“键=值”形式，
// 不猜裸值——避免把一个普通 mod id 误判成令牌。
var leakKeyPattern = []struct {
	lower string
	kind  cmdlineLeakKind
}{
	{"accesstoken", leakAccessToken},
	{"access_token", leakAccessToken},
	{"clienttoken", leakClientToken},
	{"client_token", leakClientToken},
	{"sessionid", leakSessionID},
	{"session_id", leakSessionID},
	{"authlibaccesstoken", leakAccessToken},
	{"password", leakPasswordKV},
	{"passwd", leakPasswordKV},
	{"authorization", leakAuthorization},
}

// scanCmdlineForLeaks 扫一遍参数表，返回命中列表（保持参数顺序）。
// 对每个参数，只在它以 -Dkey= / --key= / key= 形式出现时检查键名；
// 纯位置参数（jar 路径、class 名）不参与判定。
func scanCmdlineForLeaks(args []string) []CmdlineLeak {
	var out []CmdlineLeak
	for i, a := range args {
		body := strings.TrimLeft(a, "-")
		body = strings.TrimPrefix(body, "D")
		eq := strings.IndexByte(body, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(body[:eq]))
		value := strings.TrimSpace(body[eq+1:])
		if value == "" {
			continue
		}
		for _, pat := range leakKeyPattern {
			if key == pat.lower || strings.HasSuffix(key, "."+pat.lower) ||
				strings.HasSuffix(key, "_"+pat.lower) {
				out = append(out, CmdlineLeak{Index: i, Key: key, Kind: pat.kind})
				break
			}
		}
	}
	return out
}

// cmdlineHasLeakedSecrets 便捷布尔入口。
func cmdlineHasLeakedSecrets(args []string) bool {
	return len(scanCmdlineForLeaks(args)) > 0
}
