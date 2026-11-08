package main

import "strings"

// mrpackenv.go —— .mrpack 清单 files[].env 的客户端选取纯逻辑内核。
//
// Modrinth 整合包规范里，每个文件可带 env：{"client":"required|optional|unsupported",
// "server":"..."}。客户端启动器只能安装 client 侧不是 unsupported 的文件；旧实现
// 完全没有这个字段，等于把“服务器专用 mod”（client=unsupported）也下载安装到玩家
// 客户端里：既白白占用磁盘 / 下载量（与本轮磁盘预算直接相关），又可能因为服务端专用
// mod 在客户端加载而导致崩溃。
//
// 本文件只做纯函数：归一化 env 取值、判断单个文件客户端是否需要、按顺序确定性选取
// （含按规范化路径去重）。安装循环只迭代被选中的下标。

const (
	mrpackEnvKeyClient = "client"
	mrpackEnvKeyServer = "server"

	mrpackEnvRequired    = "required"
	mrpackEnvOptional    = "optional"
	mrpackEnvUnsupported = "unsupported"
)

// normalizeMrpackEnvSide 把 env 某一侧的原始取值归一化。
// 只接受规范的三个值（大小写 / 空白不敏感）；任何未知取值返回空串，由调用方按
// “未声明”对待（未知不等于 unsupported，不能据此拒绝正常文件）。
func normalizeMrpackEnvSide(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case mrpackEnvRequired:
		return mrpackEnvRequired
	case mrpackEnvOptional:
		return mrpackEnvOptional
	case mrpackEnvUnsupported:
		return mrpackEnvUnsupported
	default:
		return ""
	}
}

// mrpackClientWanted 判断某文件在“客户端安装”时是否需要下载。
//
//	env 缺失 / 没有 client 键 / client 为空：规范默认两侧都需要，返回 true；
//	client=unsupported：服务器专用，客户端跳过；
//	client=required / optional：需要；
//	任何未知取值：保守地当作需要（未知不拦，避免漏装）。
func mrpackClientWanted(env map[string]string) bool {
	if len(env) == 0 {
		return true
	}
	raw, ok := env[mrpackEnvKeyClient]
	if !ok {
		return true
	}
	return normalizeMrpackEnvSide(raw) != mrpackEnvUnsupported
}

// mrpackClientSelection 是一次客户端文件选取的结果，全部按下标表达，不拷贝文件本体。
type mrpackClientSelection struct {
	// Kept 是最终要安装的文件在原 files 切片中的下标，严格保持首次出现顺序。
	Kept []int
	// SkippedEnv 是因 client=unsupported 被跳过的下标。
	SkippedEnv []int
	// SkippedDup 是因规范化路径与更早条目重复而被跳过的下标（保留首个）。
	SkippedDup []int
}

// Count 返回被选中的文件数。
func (s mrpackClientSelection) Count() int { return len(s.Kept) }

// planClientMrpackFiles 依据 env 与规范化路径做确定性选取。
//
// 调用前置：files 已经过 validateMrpackManifest（path 已规范化、downloads 已清洗），
// 因此这里直接用 f.Path 做去重键，不再重复路径校验。规则：
//  1. client=unsupported 的文件记入 SkippedEnv，不安装；
//  2. 其余文件若其规范化路径此前已被选中，记入 SkippedDup（保留第一次出现者），
//     避免同一目标被下载 / 覆盖两次（重复写也会虚增磁盘占用）；
//  3. 其余进入 Kept，顺序与清单一致，保证安装过程可复现。
func planClientMrpackFiles(files []ModrinthModpackFile) mrpackClientSelection {
	sel := mrpackClientSelection{
		Kept:       make([]int, 0, len(files)),
		SkippedEnv: make([]int, 0),
		SkippedDup: make([]int, 0),
	}
	seenPath := make(map[string]int, len(files))
	for i := range files {
		f := files[i]
		if !mrpackClientWanted(f.Env) {
			sel.SkippedEnv = append(sel.SkippedEnv, i)
			continue
		}
		if _, exists := seenPath[f.Path]; exists {
			sel.SkippedDup = append(sel.SkippedDup, i)
			continue
		}
		seenPath[f.Path] = i
		sel.Kept = append(sel.Kept, i)
	}
	return sel
}
