package main

// modsruntimeconflictcheck.go —— mods 运行时冲突纯函数。
//
// 两个 mod 同时打了同一个 class 路径（例如都覆盖 net.minecraft.client.gui
// 的某个类），运行时会被后加载的那个静默覆盖，导致崩溃或行为诡异。这里
// 提供一个不依赖 Forge/Fabric API 的纯函数：输入 mod 列表，输出疑似冲突。

import (
	"sort"
	"strings"
)

// ModClassEntry 描述一个 mod 暴露的类路径。
type ModClassEntry struct {
	ModName  string
	ClassKey string
}

// FindModClassConflicts 输入 mods，按 classKey 分组，返回冲突列表。
// 返回的每个元素是同一个 classKey 下的 mod 名列表（已排序）。
func FindModClassConflicts(mods []ModClassEntry) [][]string {
	buckets := make(map[string][]string)
	for _, m := range mods {
		key := strings.TrimSpace(m.ClassKey)
		if key == "" {
			continue
		}
		buckets[key] = append(buckets[key], m.ModName)
	}
	out := make([][]string, 0)
	for _, names := range buckets {
		uniq := make([]string, 0, len(names))
		seen := make(map[string]bool)
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				uniq = append(uniq, n)
			}
		}
		if len(uniq) < 2 {
			continue
		}
		sort.Strings(uniq)
		out = append(out, uniq)
	}
	sort.Slice(out, func(i, j int) bool { return strings.Join(out[i], ",") < strings.Join(out[j], ",") })
	return out
}

// IsKnownAntipair 返回两个 mod 是否被硬编码为"不能同时装"。
// 命中规则：mod 名互相包含对方的反面关键词，例如 OptiFine + Sodium。
func IsKnownAntipair(a, b string) bool {
	la := strings.ToLower(a)
	lb := strings.ToLower(b)
	pairs := [][2]string{
		{"optifine", "sodium"},
		{"optifine", "iris"},
		{"sodium", "lithium-fabric"},
	}
	for _, p := range pairs {
		if (strings.Contains(la, p[0]) && strings.Contains(lb, p[1])) ||
			(strings.Contains(la, p[1]) && strings.Contains(lb, p[0])) {
			return true
		}
	}
	return false
}
