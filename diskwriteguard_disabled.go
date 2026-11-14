package main

func (g *diskWriteGuard) Disabled() bool { return g.disabled }

// Verdict 返回当前裁决（ok / short / bad-input / unknown）。
func (g *diskWriteGuard) Verdict() diskFitVerdict { return g.verdict }

// Shortfall 返回击穿水位时的缺口字节（仅 short 有意义）。
func (g *diskWriteGuard) Shortfall() int64 { return g.shortfall }

// Remaining 返回“在击穿水位前还允许写多少字节”。
// 未知（停用）返回 -1；预算已打满 / 击穿返回 0；否则返回非负可写余量。
