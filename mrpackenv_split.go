package main

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
