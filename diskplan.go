package main

// diskplan.go —— 下载开始前的“分目录落盘计划”纯逻辑内核。
//
// 单条字节预算（downloadbudget.go）回答“队列声明总量会不会超过 1TiB”；本文件回答另一个
// 更贴近物理磁盘的问题：“这批任务真的要写到各自目录时，对应卷的剩余空间够不够”。
//
// 队列里的条目可能落到不同目录（不同 SavePath，可能跨卷），把全部字节加到一个目录上
// 判余量会误报；因此先按 SavePath 分组求各目录的已知需求，再逐目录交给探测+裁决器。
// 真实探测是 probeDownloadDiskFit（平台相关），这里把它抽象成一个函数参数，使分组与
// 汇总逻辑在任意平台都能纯单测。
//
// 未知大小（SizeBytes<=0）的条目不参与字节裁决，但会被计数（UnknownItems），避免
// “全是未知大文件却显示 0 需求”的误导；未知永不导致拒绝（没证据不能拦）。

// diskDirDemand 是单个落盘目录聚合出的写入需求。
type diskDirDemand struct {
	Path         string
	KnownBytes   int64 // 该目录下所有已知大小条目之和（未知按 0）
	UnknownItems int   // 该目录下大小未知的条目数
	ItemCount    int   // 该目录下参与计划的条目总数
}

// diskDirPlan 是某目录的需求 + 磁盘裁决结果。
type diskDirPlan struct {
	Demand     diskDirDemand
	Assessment DiskFitAssessment
}

// groupDownloadDiskDemand 把下载条目按 SavePath 分组聚合。
//
//	只统计 Status=="pending" 的条目（已完成 / 已取消 / 失败的不再占空间）；
//	SavePath 为空的条目（游戏本体 / Java / loader 等落盘目录由内部决定）不纳入，
//	避免对无法确定的目录乱判；
//	输出按目录“首次出现顺序”排列，保证计划稳定、可复现，便于测试与日志对齐。
func groupDownloadDiskDemand(items []DownloadItem) []diskDirDemand {
	index := make(map[string]int)
	var demands []diskDirDemand
	for i := range items {
		it := items[i]
		if it.Status != "pending" {
			continue
		}
		dir := it.SavePath
		if dir == "" {
			continue
		}
		pos, ok := index[dir]
		if !ok {
			pos = len(demands)
			index[dir] = pos
			demands = append(demands, diskDirDemand{Path: dir})
		}
		d := &demands[pos]
		d.ItemCount++
		if it.SizeBytes > 0 {
			// 分组内求和溢出时折叠到 MaxInt64（随后裁决会因物理不可能而判 bad-input）。
			if sum, ok := addChecked(d.KnownBytes, it.SizeBytes); ok {
				d.KnownBytes = sum
			} else {
				d.KnownBytes = maxInt63()
			}
		} else {
			d.UnknownItems++
		}
	}
	return demands
}

// maxInt63 返回 math.MaxInt64，单独包一层避免在本文件再 import math。
func maxInt63() int64 { return 1<<63 - 1 }

// planDownloadDiskFit 对每个目录的已知需求做磁盘裁决。
// probe 一般传 probeDownloadDiskFit(path, requested, inflight)；测试可注入桩。
// 每个目录把本目录全部已知需求作为 requested、inflight=0 传入（因为按目录聚合后，
// 该目录所有 pending 字节就是本次将要写入的总量，requested+inflight 恒等于总需求）。
func planDownloadDiskFit(demands []diskDirDemand, probe func(path string, requested, inflight int64) DiskFitAssessment) []diskDirPlan {
	plans := make([]diskDirPlan, 0, len(demands))
	for i := range demands {
		d := demands[i]
		var assess DiskFitAssessment
		if probe == nil {
			assess = assessDiskFit(diskAvailUnknown, d.KnownBytes, 0)
		} else {
			assess = probe(d.Path, d.KnownBytes, 0)
		}
		plans = append(plans, diskDirPlan{Demand: d, Assessment: assess})
	}
	return plans
}

// blockingDiskPlans 返回会阻止下载开始的目录计划（short 或 bad-input）。
// unknown / ok 都不阻止：探测失败不误杀，空间充足放行。
func blockingDiskPlans(plans []diskDirPlan) []diskDirPlan {
	var blocked []diskDirPlan
	for i := range plans {
		v := plans[i].Assessment.Verdict
		if v == diskFitShort || v == diskFitBadInput {
			blocked = append(blocked, plans[i])
		}
	}
	return blocked
}

// describeDiskPlanBlock 汇总一个阻止计划的人类可读说明。
func describeDiskPlanBlock(p diskDirPlan) string {
	base := describeDiskFit(p.Assessment)
	if base == "" {
		return ""
	}
	return "下载目录 " + p.Demand.Path + "：" + base
}
