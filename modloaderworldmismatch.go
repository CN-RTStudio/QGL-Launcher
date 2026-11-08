package main

// modloaderworldmismatch.go —— 切换 mod loader 前的世界兼容性检查。
//
// 用户在 Forge 存档上直接切到 Fabric 启动，世界会因为 level.dat 里的 mod
// 元数据缺失而崩，甚至改坏存档。这里给一个纯函数：根据当前世界记录的
// loader 和目标 loader 给出警告等级。

import "strings"

// LoaderKind 枚举。
type LoaderKind string

const (
	LoaderVanilla  LoaderKind = "vanilla"
	LoaderForge    LoaderKind = "forge"
	LoaderFabric   LoaderKind = "fabric"
	LoaderQuilt    LoaderKind = "quilt"
	LoaderNeoForge LoaderKind = "neoforge"
)

// WorldLoaderReport 描述一个世界记录的 loader。
type WorldLoaderReport struct {
	WorldName string
	Loader    LoaderKind
	ModCount  int
}

// LoaderSwitchRisk 切换风险等级。
type LoaderSwitchRisk int

const (
	RiskOK LoaderSwitchRisk = iota
	RiskWarning
	RiskDanger
)

// AssessLoaderSwitch 比较世界记录的 loader 和目标 loader。
func AssessLoaderSwitch(world WorldLoaderReport, target LoaderKind) LoaderSwitchRisk {
	cur := strings.ToLower(string(world.Loader))
	tgt := strings.ToLower(string(target))
	if cur == "" {
		cur = string(LoaderVanilla)
	}
	if cur == tgt {
		return RiskOK
	}
	// Vanilla <-> 有 mod loader 之间，只要世界没装 mod 就只是 warning。
	if cur == string(LoaderVanilla) || tgt == string(LoaderVanilla) {
		if world.ModCount == 0 {
			return RiskWarning
		}
		return RiskDanger
	}
	// Forge <-> NeoForge 官方兼容，warning。
	if (cur == string(LoaderForge) && tgt == string(LoaderNeoForge)) ||
		(cur == string(LoaderNeoForge) && tgt == string(LoaderForge)) {
		return RiskWarning
	}
	// Fabric <-> Quilt 双向兼容。
	if (cur == string(LoaderFabric) && tgt == string(LoaderQuilt)) ||
		(cur == string(LoaderQuilt) && tgt == string(LoaderFabric)) {
		return RiskWarning
	}
	// 其他跨 loader 切换都危险。
	return RiskDanger
}

// RiskLabel 给 UI 用。
func (r LoaderSwitchRisk) RiskLabel() string {
	switch r {
	case RiskOK:
		return "ok"
	case RiskWarning:
		return "warning"
	case RiskDanger:
		return "danger"
	}
	return "unknown"
}
